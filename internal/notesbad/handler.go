package notesbad

import (
	"database/sql"
	"encoding/json"
	"go-api-security/internal/auth"
	"go-api-security/internal/web"
	"net/http"
	"strconv"
)

type Handler struct{ s *Store }

func NewHandler(s *Store) *Handler { return &Handler{s: s} }

type createReq struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

type updateReq struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// BAD: CreateNote is fine here, the access control bugs show up in read/update/delete/search.
func (h *Handler) CreateNote(w http.ResponseWriter, r *http.Request) {
	owner := auth.UserFromContext(r.Context())
	var req createReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		web.Error(w, http.StatusBadRequest, "bad json")
		return
	}
	n, err := h.s.Create(r.Context(), owner, req.Title, req.Body)
	if err != nil {
		web.Error(w, http.StatusBadRequest, "create failed")
		return
	}
	web.WriteJSON(w, http.StatusCreated, n)
}

// BAD: SearchNotes uses the vulnerable Search which builds SQL via string concatenation.
func (h *Handler) SearchNotes(w http.ResponseWriter, r *http.Request) {
	owner := auth.UserFromContext(r.Context())
	q := r.URL.Query().Get("q") // attacker-controlled input flows into concatenated SQL
	ns, err := h.s.Search(r.Context(), owner, q)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "search failed")
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"results": ns})
}

func (h *Handler) GetNote(w http.ResponseWriter, r *http.Request) {
	owner := auth.UserFromContext(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		web.Error(w, http.StatusBadRequest, "invalid id")
		return
	}
	// BAD: Store.Get ignores owner; any user can read any id
	n, err := h.s.Get(r.Context(), owner, id)
	if err == sql.ErrNoRows {
		web.Error(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	web.WriteJSON(w, http.StatusOK, n)
}

func (h *Handler) UpdateNote(w http.ResponseWriter, r *http.Request) {
	owner := auth.UserFromContext(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		web.Error(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req updateReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		web.Error(w, http.StatusBadRequest, "bad json")
		return
	}
	// BAD: Store.Update ignores owner; any user can update any id
	n, err := h.s.Update(r.Context(), owner, id, req.Title, req.Body)
	if err == sql.ErrNoRows {
		web.Error(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "update failed")
		return
	}
	web.WriteJSON(w, http.StatusOK, n)
}

func (h *Handler) DeleteNote(w http.ResponseWriter, r *http.Request) {
	owner := auth.UserFromContext(r.Context())
	_ = owner // BAD: ignored by Store.Delete
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		web.Error(w, http.StatusBadRequest, "invalid id")
		return
	}
	// BAD: Store.Delete ignores owner; any user can delete any id
	if err := h.s.Delete(r.Context(), owner, id); err != nil {
		web.Error(w, http.StatusInternalServerError, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
