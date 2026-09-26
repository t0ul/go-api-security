package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type Store struct{ db *sql.DB }

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

type Event struct {
	ID        int64           `json:"id"`
	Owner     string          `json:"owner"`
	Action    string          `json:"action"`
	Target    string          `json:"target"`
	Meta      json.RawMessage `json:"meta"`
	CreatedAt time.Time       `json:"created_at"`
}

// Log inserts one audit event. Meta will be JSON-encoded (use small maps).
func (s *Store) Log(ctx context.Context, owner, action, target string, meta map[string]any) error {
	if s == nil || s.db == nil {
		return errors.New("nil audit store")
	}
	b, _ := json.Marshal(meta)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_events(owner, action, target, meta, created_at)
		VALUES(?,?,?,?,CURRENT_TIMESTAMP)`,
		owner, action, target, string(b))
	return err
}

// List returns the N most recent events (default 20 if limit <= 0).
func (s *Store) List(ctx context.Context, limit int) ([]Event, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, owner, action, target, meta, created_at
		FROM audit_events
		ORDER BY id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var metaStr string // scan TEXT into string, then convert to RawMessage
		if err := rows.Scan(&e.ID, &e.Owner, &e.Action, &e.Target, &metaStr, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Meta = json.RawMessage(metaStr)
		out = append(out, e)
	}
	return out, rows.Err()
}
