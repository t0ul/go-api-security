package demo

import (
	"io"
	"net/http"
)

const maxUpload = 1 << 20 // 1 MiB

// Upload enforces a strict body size and returns 413 if exceeded.
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	n, err := io.Copy(io.Discard, r.Body)
	if err != nil {
		// If MaxBytesReader trips, Go will set StatusRequestEntityTooLarge (413)
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"bytes":` + itoa(n) + `}`))
}

func itoa(n int64) string {
	// tiny int->string without fmt to keep deps minimal
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
