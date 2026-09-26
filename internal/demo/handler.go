package demo

import (
	"database/sql"
	"encoding/json"
	gocrypto "go-api-security/internal/security/crypto"
	"net/http"
)

type Handler struct{ db *sql.DB }

func NewHandler(db *sql.DB) *Handler { return &Handler{db: db} }

type creds struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	var c creds
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	hash, err := gocrypto.HashPassword(c.Password)
	if err != nil {
		http.Error(w, "hash err", http.StatusInternalServerError)
		return
	}
	if _, err := h.db.Exec(`INSERT OR REPLACE INTO users(email, pass_hash) VALUES(?,?)`, c.Email, hash); err != nil {
		http.Error(w, "db err", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"email":  c.Email,
		"stored": "bcrypt",
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var c creds
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	var hash string
	if err := h.db.QueryRow(`SELECT pass_hash FROM users WHERE email=?`, c.Email).Scan(&hash); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ok := gocrypto.CheckPassword(hash, c.Password) == nil
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": ok})
}

func (h *Handler) Dump(w http.ResponseWriter, r *http.Request) {
	type row struct{ Email, PassHash string }
	rows, err := h.db.Query(`SELECT email, pass_hash FROM users ORDER BY email`)
	if err != nil {
		http.Error(w, "db err", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var rr row
		if err := rows.Scan(&rr.Email, &rr.PassHash); err != nil {
			http.Error(w, "db err", http.StatusInternalServerError)
			return
		}
		// redact by default, but show short prefix so learners can see hashes differ
		short := rr.PassHash
		if len(short) > 18 {
			short = short[:18] + "…"
		}
		out = append(out, map[string]string{"email": rr.Email, "pass_hash_preview": short})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
