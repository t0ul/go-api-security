package notes

import (
	"context"
	"database/sql"
	"errors"
)

type Store struct{ db *sql.DB }

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

var ErrNotFound = errors.New("note not found")

func (s *Store) Create(ctx context.Context, owner, title, body string) (Note, error) {
	if owner == "" || title == "" || body == "" {
		return Note{}, errors.New("missing fields")
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO notes(owner, title, body) VALUES(?,?,?)`, owner, title, body)
	if err != nil {
		return Note{}, err
	}
	id, _ := res.LastInsertId()

	var n Note
	err = s.db.QueryRowContext(ctx,
		`SELECT id, owner, title, body, created_at FROM notes WHERE id=? AND owner=?`,
		id, owner,
	).Scan(&n.ID, &n.Owner, &n.Title, &n.Body, &n.CreatedAt)
	if err != nil {
		return Note{}, err
	}
	return n, nil
}

func (s *Store) Get(ctx context.Context, owner string, id int64) (Note, error) {
	var n Note
	err := s.db.QueryRowContext(ctx,
		`SELECT id, owner, title, body, created_at
		 FROM notes WHERE id=? AND owner=?`,
		id, owner,
	).Scan(&n.ID, &n.Owner, &n.Title, &n.Body, &n.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Note{}, ErrNotFound
	}
	return n, err
}

// Search matches on title OR body (case-insensitive LIKE for ASCII), scoped to owner.
func (s *Store) Search(ctx context.Context, owner, q string) ([]Note, error) {
	like := "%" + q + "%"
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, owner, title, body, created_at
		FROM notes
		WHERE owner = ? AND (title LIKE ? OR body LIKE ?)
		ORDER BY id DESC
		LIMIT 50
	`, owner, like, like)
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

func (s *Store) Update(ctx context.Context, owner string, id int64, title, body string) (Note, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE notes SET title=?, body=? WHERE id=? AND owner=?`,
		title, body, id, owner)
	if err != nil {
		return Note{}, err
	}
	aff, _ := res.RowsAffected()
	if aff == 0 {
		return Note{}, ErrNotFound
	}
	return s.Get(ctx, owner, id)
}

func (s *Store) Delete(ctx context.Context, owner string, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM notes WHERE id=? AND owner=?`, id, owner)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}
