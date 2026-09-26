package notes

import "time"

type Note struct {
	ID        int64     `json:"id"`
	Owner     string    `json:"owner"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}
