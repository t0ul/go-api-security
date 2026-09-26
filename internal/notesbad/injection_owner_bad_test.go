package notesbad

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func badDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bad.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(`CREATE TABLE notes(
	 id INTEGER PRIMARY KEY AUTOINCREMENT,
	 owner TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
	 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func Test_Search_Bad_Leaks_OnOwnerInjection(t *testing.T) {
	db := badDB(t)
	s := NewStore(db)
	ctx := context.Background()

	_, _ = s.Create(ctx, "alice", "groceries", "eggs")
	_, _ = s.Create(ctx, "bob", "secrets", "vault")

	// Inject in owner (X-User in HTTP)
	injectedOwner := "alice' OR 1=1 -- "
	results, err := s.Search(ctx, injectedOwner, "test")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	seenBob := false
	for _, n := range results {
		if n.Owner == "bob" {
			seenBob = true
			break
		}
	}
	if !seenBob {
		t.Fatalf("expected cross-tenant leak (bob), but didn't see it")
	}
}
