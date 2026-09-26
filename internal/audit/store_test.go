package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_events(
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  owner TEXT NOT NULL,
		  action TEXT NOT NULL,
		  target TEXT NOT NULL,
		  meta   TEXT NOT NULL,
		  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestAudit_LogAndList(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()

	if err := s.Log(ctx, "alice@example.com", "http.request", "POST /notes",
		map[string]any{"status": 201, "ms": 5}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1 * time.Millisecond) // make ids/time distinct
	if err := s.Log(ctx, "alice@example.com", "http.request", "GET /notes",
		map[string]any{"status": 200, "ms": 1}); err != nil {
		t.Fatal(err)
	}

	evs, err := s.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d", len(evs))
	}
	if evs[0].Owner == "" || evs[0].Action == "" {
		t.Fatal("empty fields")
	}
}
