package limits

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"sync"
	"time"
)

// ---- In-memory Idempotency store + middleware ----

type Entry struct {
	Status    int
	Body      []byte
	BodyHash  string
	Type      string // Content-Type
	ExpiresAt time.Time
}

type IdStore struct {
	mu  sync.Mutex
	m   map[string]Entry
	ttl time.Duration
	now func() time.Time
}

func NewIdStore(ttl time.Duration) *IdStore {
	return &IdStore{
		m:   make(map[string]Entry),
		ttl: ttl,
		now: time.Now,
	}
}

func (s *IdStore) Get(key string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[key]
	if !ok {
		return Entry{}, false
	}
	if s.now().After(e.ExpiresAt) {
		delete(s.m, key)
		return Entry{}, false
	}
	return e, true
}

func (s *IdStore) Set(key string, e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = e
}

// Idempotency middleware for POST-like requests.
// Keyed by: user + method + path + Idempotency-Key.
func Idempotency(store *IdStore, keyFunc func(*http.Request) (user string), next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ik := r.Header.Get("Idempotency-Key")
		if ik == "" {
			// no key → just pass through
			next(w, r)
			return
		}
		user := keyFunc(r)
		cacheKey := user + "|" + r.Method + "|" + r.URL.Path + "|" + ik

		// Read and hash the incoming body (small payloads in this API).
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		h := sha256.Sum256(body)
		bodyHash := hex.EncodeToString(h[:])
		r.Body = io.NopCloser(bytes.NewReader(body)) // restore for downstream

		// If present: same body → replay; different body → 409.
		if e, ok := store.Get(cacheKey); ok {
			if e.BodyHash != bodyHash {
				http.Error(w, "idempotency key reused with different payload", http.StatusConflict)
				return
			}
			if e.Type != "" {
				w.Header().Set("Content-Type", e.Type)
			}
			w.WriteHeader(e.Status)
			_, _ = w.Write(e.Body)
			return
		}

		// Capture downstream response.
		rec := &captureWriter{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)

		store.Set(cacheKey, Entry{
			Status:    rec.status,
			Body:      rec.buf.Bytes(),
			BodyHash:  bodyHash,
			Type:      rec.typ,
			ExpiresAt: store.now().Add(store.ttl),
		})
	}
}

type captureWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
	typ    string
}

func (c *captureWriter) Header() http.Header { return c.ResponseWriter.Header() }
func (c *captureWriter) WriteHeader(code int) {
	c.status = code
	if t := c.Header().Get("Content-Type"); t != "" {
		c.typ = t
	}
	c.ResponseWriter.WriteHeader(code)
}
func (c *captureWriter) Write(p []byte) (int, error) {
	c.buf.Write(p) // record
	return c.ResponseWriter.Write(p)
}
