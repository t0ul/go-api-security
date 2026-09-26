package notes

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func goodDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "good.db")
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

func Test_Search_Good_NoLeak_OnOwnerInjection(t *testing.T) {
	db := goodDB(t)
	s := NewStore(db)
	ctx := context.Background()

	_, _ = s.Create(ctx, "alice", "groceries", "eggs")
	_, _ = s.Create(ctx, "bob", "secrets", "vault")

	injectedOwner := "alice' OR 1=1 -- "
	res, err := s.Search(ctx, injectedOwner, "test")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	for _, n := range res {
		if n.Owner != injectedOwner {
			t.Fatalf("leak: got owner %q (expected only literal match to injected value)", n.Owner)
		}
	}
	// In practice, there will be zero matches for that literal owner string.
}
