package demobad

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"go-api-security/internal/securitybad/cryptobad"
)

type Handler struct{ db *sql.DB }

func NewHandler(db *sql.DB) *Handler { return &Handler{db: db} }

type creds struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// ---------- PLAINTEXT (already had) ----------

func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	var c creds
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	pw := cryptobad.StorePlain(c.Password) // ❌ plaintext storage
	if _, err := h.db.Exec(`INSERT OR REPLACE INTO users_insecure(email, password) VALUES(?,?)`, c.Email, pw); err != nil {
		http.Error(w, "db err", http.StatusInternalServerError)
		return
	}
	jsonOK(w, http.StatusCreated, map[string]any{"email": c.Email, "stored": "plaintext"})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var c creds
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	var stored string
	if err := h.db.QueryRow(`SELECT password FROM users_insecure WHERE email=?`, c.Email).Scan(&stored); err != nil {
		jsonOK(w, http.StatusUnauthorized, map[string]bool{"ok": false})
		return
	}
	ok := (stored == c.Password) // ❌ direct plaintext compare
	jsonOK(w, http.StatusOK, map[string]bool{"ok": ok})
}

func (h *Handler) Dump(w http.ResponseWriter, r *http.Request) {
	type row struct{ Email, Password string }
	rows, err := h.db.Query(`SELECT email, password FROM users_insecure ORDER BY email`)
	if err != nil {
		http.Error(w, "db err", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []row{}
	for rows.Next() {
		var rr row
		if err := rows.Scan(&rr.Email, &rr.Password); err != nil {
			http.Error(w, "db err", http.StatusInternalServerError)
			return
		}
		out = append(out, rr)
	}
	jsonOK(w, http.StatusOK, out)
}

// ---------- SHA-1 (unsalted, fast) ----------

func (h *Handler) SignupSHA1(w http.ResponseWriter, r *http.Request) {
	var c creds
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	hash := cryptobad.HashSHA1(c.Password) // ❌ fast, unsalted
	if _, err := h.db.Exec(`INSERT OR REPLACE INTO users_sha1(email, sha1) VALUES(?,?)`, c.Email, hash); err != nil {
		http.Error(w, "db err", http.StatusInternalServerError)
		return
	}
	jsonOK(w, http.StatusCreated, map[string]any{"email": c.Email, "stored": "sha1"})
}

func (h *Handler) LoginSHA1(w http.ResponseWriter, r *http.Request) {
	var c creds
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	var stored string
	if err := h.db.QueryRow(`SELECT sha1 FROM users_sha1 WHERE email=?`, c.Email).Scan(&stored); err != nil {
		jsonOK(w, http.StatusUnauthorized, map[string]bool{"ok": false})
		return
	}
	ok := (stored == cryptobad.HashSHA1(c.Password))
	jsonOK(w, http.StatusOK, map[string]bool{"ok": ok})
}

func (h *Handler) DumpSHA1(w http.ResponseWriter, r *http.Request) {
	type row struct{ Email, SHA1 string }
	rows, err := h.db.Query(`SELECT email, sha1 FROM users_sha1 ORDER BY email`)
	if err != nil {
		http.Error(w, "db err", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []row{}
	for rows.Next() {
		var rr row
		if err := rows.Scan(&rr.Email, &rr.SHA1); err != nil {
			http.Error(w, "db err", http.StatusInternalServerError)
			return
		}
		out = append(out, rr)
	}
	jsonOK(w, http.StatusOK, out)
}

// ---------- MD5 (unsalted, collision-prone) ----------

func (h *Handler) SignupMD5(w http.ResponseWriter, r *http.Request) {
	var c creds
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	hash := cryptobad.HashMD5(c.Password) // ❌ fast, unsalted, weak
	if _, err := h.db.Exec(`INSERT OR REPLACE INTO users_md5(email, md5) VALUES(?,?)`, c.Email, hash); err != nil {
		http.Error(w, "db err", http.StatusInternalServerError)
		return
	}
	jsonOK(w, http.StatusCreated, map[string]any{"email": c.Email, "stored": "md5"})
}

func (h *Handler) LoginMD5(w http.ResponseWriter, r *http.Request) {
	var c creds
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	var stored string
	if err := h.db.QueryRow(`SELECT md5 FROM users_md5 WHERE email=?`, c.Email).Scan(&stored); err != nil {
		jsonOK(w, http.StatusUnauthorized, map[string]bool{"ok": false})
		return
	}
	ok := (stored == cryptobad.HashMD5(c.Password))
	jsonOK(w, http.StatusOK, map[string]bool{"ok": ok})
}

func (h *Handler) DumpMD5(w http.ResponseWriter, r *http.Request) {
	type row struct{ Email, MD5 string }
	rows, err := h.db.Query(`SELECT email, md5 FROM users_md5 ORDER BY email`)
	if err != nil {
		http.Error(w, "db err", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []row{}
	for rows.Next() {
		var rr row
		if err := rows.Scan(&rr.Email, &rr.MD5); err != nil {
			http.Error(w, "db err", http.StatusInternalServerError)
			return
		}
		out = append(out, rr)
	}
	jsonOK(w, http.StatusOK, out)
}

// ---------- helpers ----------
func jsonOK(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------- SHA-1 / MD5 OFFLINE CRACK DEMOS ----------

type crackReq struct {
	Hash string `json:"hash"`
}

func (h *Handler) CrackSHA1(w http.ResponseWriter, r *http.Request) {
	var req crackReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	for i, p := range commonPasswords() {
		if cryptobad.HashSHA1(p) == req.Hash {
			jsonOK(w, http.StatusOK, map[string]any{
				"found": true, "password": p, "tries": i + 1, "algo": "sha1",
			})
			return
		}
	}
	jsonOK(w, http.StatusOK, map[string]any{"found": false, "tries": len(commonPasswords()), "algo": "sha1"})
}

func (h *Handler) CrackMD5(w http.ResponseWriter, r *http.Request) {
	var req crackReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	for i, p := range commonPasswords() {
		if cryptobad.HashMD5(p) == req.Hash {
			jsonOK(w, http.StatusOK, map[string]any{
				"found": true, "password": p, "tries": i + 1, "algo": "md5",
			})
			return
		}
	}
	jsonOK(w, http.StatusOK, map[string]any{"found": false, "tries": len(commonPasswords()), "algo": "md5"})
}

func commonPasswords() []string {
	// Tiny demo list. You can expand for class.
	return []string{
		"123456", "password", "qwerty", "letmein", "admin",
		"welcome", "iloveyou", "monkey", "dragon", "football",
		"baseball", "abc123", "trustno1", "p@ssw0rd", "hunter2",
	}
}
