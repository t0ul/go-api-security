package demobad

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
)

// POST /hooks/register_bad (PUBLIC in bad world)
// Returns a "secret" but we won't actually use it for verification.
func (h *Handler) RegisterHookBad(w http.ResponseWriter, r *http.Request) {
	type req struct {
		Owner string `json:"owner"`
	}
	var rr req
	_ = json.NewDecoder(r.Body).Decode(&rr)
	if rr.Owner == "" {
		rr.Owner = "anonymous"
	}

	sec := make([]byte, 16)
	_, _ = rand.Read(sec)
	hexSecret := hex.EncodeToString(sec)

	_, _ = h.db.Exec(`INSERT INTO webhook_secrets_bad(owner, secret, created_at)
		VALUES(?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(owner) DO UPDATE SET secret=excluded.secret, created_at=CURRENT_TIMESTAMP`,
		rr.Owner, hexSecret)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"owner":  rr.Owner,
		"secret": hexSecret,
	})
}

// POST /hooks/ingest_bad/{owner} (PUBLIC)
// ❌ Doesn’t check signatures at all; just writes a note.
func (h *Handler) IngestHookBad(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("owner")
	if owner == "" {
		http.Error(w, "missing owner", http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(r.Body)
	_, err := h.db.Exec(`INSERT INTO notes(owner, title, body) VALUES(?,?,?)`,
		owner, "webhook(BAD)", string(body))
	if err != nil {
		http.Error(w, "db err", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}
