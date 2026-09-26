package main

import (
	"context"
	"database/sql"
	"go-api-security/internal/authbad"
	"go-api-security/internal/demobad"
	"go-api-security/internal/notesbad"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

func main() {
	ctx := context.Background()

	db, err := sql.Open("sqlite", "file:notes_bad.db?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if err := migrate(ctx, db); err != nil {
		log.Fatal(err)
	}

	// Handlers
	store := notesbad.NewStore(db)
	h := notesbad.NewHandler(store)
	d := demobad.NewHandler(db)

	// PROTECTED API (but "protected" by BAD JWT that doesn't verify signatures)
	api := http.NewServeMux()
	api.HandleFunc("POST /notes", h.CreateNote)
	api.HandleFunc("GET /notes", h.SearchNotes)
	api.HandleFunc("GET /notes/{id}", h.GetNote)
	api.HandleFunc("PUT /notes/{id}", h.UpdateNote)
	api.HandleFunc("DELETE /notes/{id}", h.DeleteNote)

	// PUBLIC demo/auth
	demoMux := http.NewServeMux()
	demoMux.HandleFunc("POST /demo/signup", d.Signup)
	demoMux.HandleFunc("POST /demo/login", d.Login)
	demoMux.HandleFunc("GET /demo/dump", d.Dump)
	demoMux.HandleFunc("POST /demo/signup_sha1", d.SignupSHA1)
	demoMux.HandleFunc("POST /demo/login_sha1", d.LoginSHA1)
	demoMux.HandleFunc("GET /demo/dump_sha1", d.DumpSHA1)
	demoMux.HandleFunc("POST /demo/signup_md5", d.SignupMD5)
	demoMux.HandleFunc("POST /demo/login_md5", d.LoginMD5)
	demoMux.HandleFunc("GET /demo/dump_md5", d.DumpMD5)
	demoMux.HandleFunc("POST /demo/upload", d.Upload)
	// BAD JWT login that issues unsigned tokens
	demoMux.HandleFunc("POST /auth/login_none", d.LoginJWTNone)
	demoMux.HandleFunc("POST /hooks/register_bad", d.RegisterHookBad)
	demoMux.HandleFunc("POST /hooks/ingest_bad/{owner}", d.IngestHookBad)

	// Root: /demo & /auth public; "/" "protected" by BAD JWT
	root := http.NewServeMux()
	root.Handle("/demo/", demoMux)
	root.Handle("/auth/", demoMux)
	// Mount the two BAD webhook routes directly:
	root.HandleFunc("POST /hooks/ingest_bad/{owner}", d.IngestHookBad)
	root.HandleFunc("POST /hooks/register_bad", d.RegisterHookBad)
	root.HandleFunc("GET /ssrf/fetch_bad", d.SSRFFetchBad)
	root.Handle("/", authbad.JWTAny(authbad.BadConfig{Iss: "go-api-security-bad", Aud: "notes-api"})(api))

	// Public pprof (still from A05)
	root.HandleFunc("/debug/pprof/", pprof.Index)
	root.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	root.HandleFunc("/debug/pprof/profile", pprof.Profile)
	root.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	root.HandleFunc("/debug/pprof/trace", pprof.Trace)

	addr := env("ADDR", ":8081")
	srv := &http.Server{
		Addr:    addr,
		Handler: logging(badCORS(root)),
	}
	log.Printf("BAD API (no JWT verify) listening on %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
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
	CREATE TABLE IF NOT EXISTS users_insecure (
	  email TEXT PRIMARY KEY,
	  password TEXT NOT NULL,
	  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS users_sha1 (
	  email TEXT PRIMARY KEY,
	  sha1  TEXT NOT NULL,
	  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS users_md5 (
	  email TEXT PRIMARY KEY,
	  md5   TEXT NOT NULL,
	  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS webhook_secrets_bad (
	  owner TEXT PRIMARY KEY,
	  secret TEXT NOT NULL,
	  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
`)
	return err
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func badCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
