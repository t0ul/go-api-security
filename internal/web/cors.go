package web

import (
	"net/http"
	"os"
	"strings"
)

func CORSFromEnv() func(http.Handler) http.Handler {
	// ALLOWED_ORIGINS comma-separated, e.g. "http://localhost:5173,https://myapp.com"
	raw := os.Getenv("ALLOWED_ORIGINS")
	allowed := []string{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			allowed = append(allowed, p)
		}
	}
	return CORS(allowed)
}

func CORS(allowed []string) func(http.Handler) http.Handler {
	allow := func(origin string) bool {
		for _, a := range allowed {
			if origin == a {
				return true
			}
		}
		return false
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allow(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			}

			if r.Method == http.MethodOptions {
				// Preflight handled here (even if not allowed, we still return 204)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
