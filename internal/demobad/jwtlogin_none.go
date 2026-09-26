package demobad

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"go-api-security/internal/authbad"
)

type loginReq struct {
	Email string `json:"email"`
}

type loginResp struct {
	Token string `json:"token"`
}

func (h *Handler) LoginJWTNone(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	iss := env("AUTH_ISS", "go-api-security-bad")
	aud := env("AUTH_AUD", "notes-api")
	tok := authbad.IssueNone(req.Email, iss, aud, 24*time.Hour) // ❌ very long TTL, unsigned
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResp{Token: tok})
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
