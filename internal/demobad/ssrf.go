package demobad

import (
	"io"
	"net/http"
)

// GET /ssrf/fetch_bad?url=...
// ❌ No scheme/host checks, no DNS vetting, no redirect checks, no size/timeout bounds.
func (h *Handler) SSRFFetchBad(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	resp, err := http.Get(raw) // follows redirects, resolves localhost, etc.
	if err != nil {
		http.Error(w, "fetch err: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body) // unbounded passthrough
}
