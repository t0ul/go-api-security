package authbad

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"go-api-security/internal/auth"
)

// BadConfig is unused today but kept for parity with the good path.
type BadConfig struct {
	Iss string
	Aud string
}

// JWTAny accepts any "JWT" by decoding payload only (❌ no signature check).
// It STILL sets the user into the SAME context key the handlers read.
func JWTAny(_ BadConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			parts := strings.Split(strings.TrimPrefix(h, "Bearer "), ".")
			if len(parts) < 2 {
				http.Error(w, "bad token", http.StatusUnauthorized)
				return
			}
			// decode payload only (no verification)
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				http.Error(w, "bad token", http.StatusUnauthorized)
				return
			}
			var c struct {
				Sub string `json:"sub"`
			}
			_ = json.Unmarshal(payload, &c)
			if c.Sub == "" {
				http.Error(w, "bad token", http.StatusUnauthorized)
				return
			}

			ctx := auth.ContextWithUser(r.Context(), c.Sub)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// IssueNone returns an unsigned JWT: header.alg="none", no signature (❌).
func IssueNone(sub, iss, aud string, ttl time.Duration) string {
	h := `{"alg":"none","typ":"JWT"}`
	now := time.Now().Unix()
	exp := time.Now().Add(ttl).Unix()
	p := map[string]any{"sub": sub, "iss": iss, "aud": aud, "iat": now, "exp": exp}
	bp, _ := json.Marshal(p)
	return b64(h) + "." + b64(string(bp)) + "." // empty signature
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
