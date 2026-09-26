package admin

import (
	"encoding/json"
	"net/http"
	"strconv"

	"go-api-security/internal/audit"
)

type Handler struct{ A *audit.Store }

func NewHandler(a *audit.Store) *Handler { return &Handler{A: a} }

func (h *Handler) ListAudit(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	evs, err := h.A.List(r.Context(), limit)
	if err != nil {
		http.Error(w, "audit list error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(evs)
}
