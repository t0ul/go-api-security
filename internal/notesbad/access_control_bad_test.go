package notesbad

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bad.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(`
CREATE TABLE notes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner TEXT NOT NULL,
  title TEXT NOT NULL,
  body  TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func Test_BrokenAccessControl_AllowsCrossTenantOps(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()

	alice, err := s.Create(ctx, "alice", "a", "x")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.Create(ctx, "bob", "b", "y")
	if err != nil {
		t.Fatal(err)
	}

	// ❌ Read: Alice can read Bob's note by id
	got, err := s.Get(ctx, "alice", bob.ID)
	if err != nil {
		t.Fatalf("expected to read bob's note, err=%v", err)
	}
	if got.Owner != "bob" {
		t.Fatalf("expected owner bob, got %s", got.Owner)
	}

	// ❌ Update: Alice can update Bob's note
	updated, err := s.Update(ctx, "alice", bob.ID, "pwned", "oops")
	if err != nil {
		t.Fatalf("expected to update bob's note, err=%v", err)
	}
	if updated.Title != "pwned" {
		t.Fatalf("update didn't apply, got %q", updated.Title)
	}

	// ❌ Delete: Alice can delete Bob's note
	if err := s.Delete(ctx, "alice", bob.ID); err != nil {
		t.Fatalf("expected to delete bob's note, err=%v", err)
	}

	// Control: Alice can still read her own note
	if _, err := s.Get(ctx, "alice", alice.ID); err != nil {
		t.Fatalf("own read failed, err=%v", err)
	}
}
