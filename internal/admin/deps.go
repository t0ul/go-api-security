package admin

import (
	"encoding/json"
	"net/http"

	"go-api-security/internal/deps"
)

func (h *Handler) ListDeps(w http.ResponseWriter, r *http.Request) {
	findings, err := deps.EvaluateBuild()
	if err != nil {
		http.Error(w, "deps error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(findings)
}
