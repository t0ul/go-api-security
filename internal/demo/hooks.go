package demo

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"go-api-security/internal/auth"
	"go-api-security/internal/security/hmacsig"
)

type secretRow struct {
	Owner  string
	Secret string
}

// POST /hooks/register  (JWT-protected)
// Creates or rotates a per-owner secret and returns it (show once).
func (h *Handler) RegisterHook(w http.ResponseWriter, r *http.Request) {
	owner := auth.UserFromContext(r.Context())
	if owner == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	sec := make([]byte, 32)
	if _, err := rand.Read(sec); err != nil {
		http.Error(w, "entropy err", http.StatusInternalServerError)
		return
	}
	hexSecret := hex.EncodeToString(sec)

	_, err := h.db.Exec(`INSERT INTO webhook_secrets(owner, secret, created_at)
		VALUES(?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(owner) DO UPDATE SET secret=excluded.secret, created_at=CURRENT_TIMESTAMP`,
		owner, hexSecret)
	if err != nil {
		http.Error(w, "db err", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"owner":  owner,
		"secret": hexSecret, // in real life, show once
	})
}

// POST /hooks/ingest/{owner}  (PUBLIC)
// Verifies X-Signature + X-Timestamp with the stored secret.
// On success, writes a "webhook: ..." note for that owner.
func (h *Handler) IngestHook(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("owner")
	if owner == "" {
		http.Error(w, "missing owner", http.StatusBadRequest)
		return
	}

	// Fetch secret
	var hexSecret string
	if err := h.db.QueryRow(`SELECT secret FROM webhook_secrets WHERE owner=?`, owner).Scan(&hexSecret); err != nil {
		http.Error(w, "unknown owner", http.StatusNotFound)
		return
	}
	sec, err := hex.DecodeString(hexSecret)
	if err != nil {
		http.Error(w, "server secret decode err", http.StatusInternalServerError)
		return
	}

	// Read with small limit
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}

	ts := r.Header.Get("X-Timestamp")
	sig := r.Header.Get("X-Signature")
	if ts == "" || sig == "" {
		http.Error(w, "missing signature headers", http.StatusUnauthorized)
		return
	}

	if err := hmacsig.Verify(sec, ts, sig, body, 5*time.Minute); err != nil {
		http.Error(w, "invalid signature: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Insert a note for the owner
	_, err = h.db.Exec(`INSERT INTO notes(owner, title, body) VALUES(?,?,?)`,
		owner, "webhook", string(body))
	if err != nil {
		http.Error(w, "db err", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"owner":    owner,
		"received": len(body),
		"ts":       ts,
	})
}

// Helper for clients to compute a timestamp (not required; just nice)
func NowUnix() string { return strconv.FormatInt(time.Now().Unix(), 10) }
