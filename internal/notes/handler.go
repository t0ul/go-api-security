package notes

import (
	"encoding/json"
	"net/http"
	"strconv"

	"go-api-security/internal/auth"
)

type Handler struct{ s *Store }

func NewHandler(s *Store) *Handler { return &Handler{s: s} }

type noteReq struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

func (h *Handler) CreateNote(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req noteReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	n, err := h.s.Create(r.Context(), user, req.Title, req.Body)
	if err != nil {
		http.Error(w, "create failed", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Return { "id": <int>, "owner": "...", ... } — capstone test reads "id"
	_ = json.NewEncoder(w).Encode(n)
}

func (h *Handler) GetNote(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	n, err := h.s.Get(r.Context(), user, id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(n)
}

func (h *Handler) SearchNotes(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query().Get("q")
	notes, err := h.s.Search(r.Context(), user, q)
	if err != nil {
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(notes)
}

func (h *Handler) UpdateNote(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req noteReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	n, err := h.s.Update(r.Context(), user, id, req.Title, req.Body)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(n)
}

func (h *Handler) DeleteNote(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := h.s.Delete(r.Context(), user, id); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
