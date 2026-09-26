package web

import (
	"encoding/json"
	"net/http"
)

type ErrorEnvelope struct {
	Error string `json:"error"`
}

func WriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func Error(w http.ResponseWriter, code int, msg string) {
	WriteJSON(w, code, ErrorEnvelope{Error: msg})
}
