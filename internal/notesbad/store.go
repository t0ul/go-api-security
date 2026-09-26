package notesbad

import (
	"context"
	"database/sql"
	"errors"
	"go-api-security/internal/securitybad/sqlbad"
	"time"
)

type Note struct {
	ID        int64     `json:"id"`
	Owner     string    `json:"owner"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

type Store struct{ db *sql.DB }

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) Create(ctx context.Context, owner, title, body string) (Note, error) {
	if owner == "" || title == "" || body == "" {
		return Note{}, errors.New("missing fields")
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO notes(owner,title,body) VALUES(?,?,?)`, owner, title, body)
	if err != nil {
		return Note{}, err
	}
	id, _ := res.LastInsertId()
	var n Note
	// 🚨 BAD: select by id only (no owner filter)
	err = s.db.QueryRowContext(ctx,
		`SELECT id, owner, title, body, created_at FROM notes WHERE id=?`, id).
		Scan(&n.ID, &n.Owner, &n.Title, &n.Body, &n.CreatedAt)
	return n, err
}

func (s *Store) Get(ctx context.Context, _owner string, id int64) (Note, error) {
	var n Note
	// 🚨 BAD: no owner filter → any user can read any id
	err := s.db.QueryRowContext(ctx, `
SELECT id, owner, title, body, created_at
FROM notes
WHERE id = ?`, id).
		Scan(&n.ID, &n.Owner, &n.Title, &n.Body, &n.CreatedAt)
	return n, err
}

func (s *Store) Update(ctx context.Context, _owner string, id int64, title, body string) (Note, error) {
	// 🚨 BAD: no owner filter → any user can update any id
	if _, err := s.db.ExecContext(ctx, `
UPDATE notes SET title = ?, body = ? WHERE id = ?`, title, body, id); err != nil {
		return Note{}, err
	}
	return s.Get(ctx, "", id)
}

func (s *Store) Delete(ctx context.Context, _owner string, id int64) error {
	// 🚨 BAD: no owner filter → any user can delete any id
	_, err := s.db.ExecContext(ctx, `DELETE FROM notes WHERE id = ?`, id)
	return err
}

func (s *Store) Search(ctx context.Context, owner, q string) ([]Note, error) {
	stmt := sqlbad.BuildSearch(owner, q)      // 🚨 concat SQL with user input
	rows, err := s.db.QueryContext(ctx, stmt) // no args → injection lands
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Note
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.Owner, &n.Title, &n.Body, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
