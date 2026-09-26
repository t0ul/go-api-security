package demo

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"go-api-security/internal/auth"
	gocrypto "go-api-security/internal/security/crypto"
)

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type loginResp struct {
	Token string `json:"token"`
}

func (h *Handler) LoginJWT(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	var hash string
	if err := h.db.QueryRow(`SELECT pass_hash FROM users WHERE email=?`, req.Email).Scan(&hash); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if gocrypto.CheckPassword(hash, req.Password) != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	cfg := auth.JWTConfig{
		Secret: []byte(env("AUTH_SECRET", "dev-secret-32bytes-please-please!!")),
		Iss:    env("AUTH_ISS", "go-api-security"),
		Aud:    env("AUTH_AUD", "notes-api"),
		Skew:   2 * time.Second,
	}
	tok, err := auth.IssueJWT(req.Email, 15*time.Minute, cfg)
	if err != nil {
		http.Error(w, "issue token err", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResp{Token: tok})
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
