package app

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"time"

	"go-api-security/internal/admin"
	"go-api-security/internal/audit"
	"go-api-security/internal/auth"
	"go-api-security/internal/demo"
	"go-api-security/internal/limits"
	"go-api-security/internal/notes"
	"go-api-security/internal/web"
)

func BuildGoodMux(ctx context.Context, db *sql.DB) (http.Handler, error) {
	if err := migrate(ctx, db); err != nil {
		return nil, err
	}

	// handlers
	store := notes.NewStore(db)
	n := notes.NewHandler(store)
	d := demo.NewHandler(db)
	aud := audit.NewStore(db)
	adm := admin.NewHandler(aud)

	// A04: rate limit + idempotency
	lim := limits.NewLimiter(5, 8)
	ids := limits.NewIdStore(10 * time.Minute)

	// JWT config
	jcfg := auth.JWTConfig{
		Secret: []byte(env("AUTH_SECRET", "dev-secret-32bytes-please-please!!")),
		Iss:    env("AUTH_ISS", "go-api-security"),
		Aud:    env("AUTH_AUD", "notes-api"),
		Skew:   2 * time.Second,
	}

	// --- API (JWT-protected) ---
	api := http.NewServeMux()
	// notes
	api.HandleFunc("POST /notes", limits.Idempotency(ids, func(r *http.Request) string {
		return auth.UserFromContext(r.Context())
	}, n.CreateNote))
	api.HandleFunc("GET /notes", n.SearchNotes)
	api.HandleFunc("GET /notes/{id}", n.GetNote)
	api.HandleFunc("PUT /notes/{id}", n.UpdateNote)
	api.HandleFunc("DELETE /notes/{id}", n.DeleteNote)
	// webhooks (register)
	api.HandleFunc("POST /hooks/register", d.RegisterHook)
	// admin
	api.HandleFunc("GET /admin/audit", adm.ListAudit)
	api.HandleFunc("GET /admin/deps", adm.ListDeps)

	// --- Public demo/auth ---
	pub := http.NewServeMux()
	pub.HandleFunc("POST /demo/signup", d.Signup)
	pub.HandleFunc("POST /demo/login", d.Login)
	pub.HandleFunc("GET /demo/dump", d.Dump)
	pub.HandleFunc("POST /demo/upload", d.Upload)
	// A07 auth
	pub.HandleFunc("POST /auth/login", d.LoginJWT)
	// A08 webhook ingest (public, signature verified in handler)
	pub.HandleFunc("POST /hooks/ingest/{owner}", d.IngestHook)
	// A10 safe SSRF (public)
	pub.HandleFunc("GET /ssrf/fetch", d.SSRFFetchSafe)

	// --- Root composition ---
	root := http.NewServeMux()
	// public first
	root.Handle("/demo/", pub)
	root.Handle("/auth/", pub)
	root.HandleFunc("POST /hooks/ingest/{owner}", d.IngestHook)
	root.HandleFunc("GET /ssrf/fetch", d.SSRFFetchSafe)

	// protected: JWT -> API -> audit -> rate limit
	protectedCore := auth.JWTAuth(jcfg)(api)
	protectedWithAudit := web.SecurityHeaders(web.CORSFromEnv()(auditMW(aud)(protectedCore)))
	protected := limits.RateLimit(lim, func(r *http.Request) string {
		return limits.KeyUserOrIP(r, auth.UserFromContext(r.Context()))
	})(protectedWithAudit)

	root.Handle("/", protected)

	// top-level logging
	return logging(root), nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner TEXT NOT NULL,
  title TEXT NOT NULL,
  body  TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
  email TEXT PRIMARY KEY,
  pass_hash TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS webhook_secrets (
  owner TEXT PRIMARY KEY,
  secret TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  meta   TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`)
	return err
}

func auditMW(a *audit.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			cw := &cap{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(cw, r)
			_ = a.Log(r.Context(),
				auth.UserFromContext(r.Context()),
				"http.request",
				r.Method+" "+r.URL.Path,
				map[string]any{"status": cw.status, "ms": time.Since(start).Milliseconds()},
			)
		})
	}
}

type cap struct {
	http.ResponseWriter
	status int
}

func (c *cap) WriteHeader(code int) { c.status = code; c.ResponseWriter.WriteHeader(code) }

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		_ = start // keep it minimal; detailed logging handled elsewhere
	})
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
