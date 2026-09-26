package main

import (
	"context"
	"database/sql"
	"go-api-security/internal/app"
	"log"
	"net/http"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

func main() {
	ctx := context.Background()

	// Open SQLite (same settings we've used throughout)
	db, err := sql.Open("sqlite", "file:notes.db?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// Build the GOOD server mux (wires auth, limits, audit, deps, webhook HMAC, SSRF guard, etc.)
	mux, err := app.BuildGoodMux(ctx, db)
	if err != nil {
		log.Fatal(err)
	}

	// Minimal, safe-ish server config
	srv := &http.Server{
		Addr:              env("ADDR", ":8080"),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("GOOD API (capstone) listening on %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
