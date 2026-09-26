package auth

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey string

const userKey ctxKey = "user"

// ContextWithUser lets other packages (e.g., authbad) set the user
// using the same internal context key your handlers already read.
func ContextWithUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, userKey, user)
}

// JWTAuth enforces Authorization: Bearer <token>, verifies, and sets user in context.
func JWTAuth(cfg JWTConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			sub, err := VerifyJWT(strings.TrimPrefix(h, "Bearer "), cfg)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			ctx := ContextWithUser(r.Context(), sub)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// WithUser (older lessons) — unchanged
func WithUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.Header.Get("X-User")
		if u == "" {
			http.Error(w, "missing X-User", http.StatusUnauthorized)
			return
		}
		ctx := ContextWithUser(r.Context(), u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func UserFromContext(ctx context.Context) string {
	v, _ := ctx.Value(userKey).(string)
	return v
}
