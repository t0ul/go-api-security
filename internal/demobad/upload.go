package demobad

import (
	"io"
	"net/http"
)

// Upload reads the entire body without any bound (bad).
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body) // ❌ unbounded read
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"bytes":` + itoa(int64(len(b))) + `}`))
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + (n % 10))
		n /= 10
	}
	return string(buf[i:])
}
