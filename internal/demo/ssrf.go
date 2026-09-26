package demo

import (
	"io"
	"net/http"
	"os"
	"strings"

	"go-api-security/internal/security/urlguard"
)

const maxPreview = 2048     // bytes returned to caller
const maxDownload = 1 << 20 // 1 MiB read cap

// GET /ssrf/fetch?url=...
// Public demo endpoint that safely fetches a URL with SSRF guards.
func (h *Handler) SSRFFetchSafe(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	u, err := urlguard.ParseAndValidate(raw)
	if err != nil {
		http.Error(w, "bad url: "+err.Error(), http.StatusBadRequest)
		return
	}

	allow := parseCSV(os.Getenv("SSRF_ALLOW_HOSTS")) // optional
	cfg := urlguard.DefaultConfig()
	cfg.AllowHosts = allow
	client := urlguard.BuildSafeClient(cfg)

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u.String(), nil)
	if err != nil {
		http.Error(w, "req err", http.StatusInternalServerError)
		return
	}
	req.Header.Set("User-Agent", "go-api-security-ssrf-safe/1.0")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "fetch blocked: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	// Bound how much we read/echo back
	limited := io.LimitReader(resp.Body, maxDownload)
	body, err := io.ReadAll(limited)
	if err != nil {
		http.Error(w, "read err", http.StatusBadGateway)
		return
	}
	if len(body) > maxPreview {
		body = body[:maxPreview]
	}

	// Return a small JSON envelope with a preview, not raw passthrough.
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":`))
	_, _ = w.Write([]byte(intToStr(resp.StatusCode)))
	_, _ = w.Write([]byte(`,"preview":"` + jsonEscape(string(body)) + `"}`))
}

// tiny helpers (avoid fmt/encoding/json for brevity)
func jsonEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	b := [12]byte{}
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
