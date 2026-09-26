package notes

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
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
CREATE INDEX idx_notes_owner_created ON notes(owner, created_at DESC);
`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestOwnerIsolation_GetUpdateDelete(t *testing.T) {
	db := testDB(t)
	s := NewStore(db)
	ctx := context.Background()

	aliceNote, err := s.Create(ctx, "alice", "a", "x")
	if err != nil {
		t.Fatal(err)
	}
	bobNote, err := s.Create(ctx, "bob", "b", "y")
	if err != nil {
		t.Fatal(err)
	}

	// Alice cannot read Bob's note
	if _, err := s.Get(ctx, "alice", bobNote.ID); err == nil {
		t.Fatal("expected sql.ErrNoRows for cross-owner Get")
	}

	// Alice cannot update Bob's note
	if _, err := s.Update(ctx, "alice", bobNote.ID, "hack", "hack"); err == nil {
		t.Fatal("expected sql.ErrNoRows for cross-owner Update")
	}

	// Alice cannot delete Bob's note
	if err := s.Delete(ctx, "alice", bobNote.ID); err == nil {
		t.Fatal("expected sql.ErrNoRows for cross-owner Delete")
	}

	// But she can update her own
	if _, err := s.Update(ctx, "alice", aliceNote.ID, "new", "body"); err != nil {
		t.Fatalf("own Update failed: %v", err)
	}
}
