package logs

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"go-api-security/internal/audit"
	"go-api-security/internal/auth"
)

type capWriter struct {
	http.ResponseWriter
	status int
}

func (c *capWriter) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

func clientIP(r *http.Request) string {
	// Prefer X-Forwarded-For first hop if present (demo only).
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// AuditRequests writes one audit row per request after it's served.
// It redacts Authorization and doesn't record request bodies.
func AuditRequests(store *audit.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			cw := &capWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(cw, r)

			owner := auth.UserFromContext(r.Context())
			target := r.Method + " " + r.URL.Path
			meta := map[string]any{
				"status": cw.status,
				"ms":     time.Since(start).Milliseconds(),
				"ip":     clientIP(r),
				"ua":     r.UserAgent(),
				// For demo, capture a sanitized set of headers:
				"headers": sanitizeHeaders(r.Header),
				"q":       r.URL.RawQuery,
			}
			_ = store.Log(r.Context(), owner, "http.request", target, meta)
		})
	}
}

func sanitizeHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		if len(v) == 0 {
			continue
		}
		switch strings.ToLower(k) {
		case "authorization", "cookie", "x-api-key":
			out[k] = "***redacted***"
		default:
			// Join but cap length to avoid log bloat.
			val := strings.Join(v, ",")
			if len(val) > 200 {
				val = val[:200] + "…"
			}
			out[k] = val
		}
	}
	// pretty stable order not guaranteed; OK for demo
	_, _ = json.Marshal(out) // ensure it's JSON-serializable
	return out
}
