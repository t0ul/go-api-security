package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORS_Allowlist(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	s := httptest.NewServer(CORS([]string{"http://good.test"})(h))
	defer s.Close()

	req, _ := http.NewRequest("GET", s.URL, nil)
	req.Header.Set("Origin", "http://good.test")
	res, _ := http.DefaultClient.Do(req)
	if got := res.Header.Get("Access-Control-Allow-Origin"); got != "http://good.test" {
		t.Fatalf("want ACAO=http://good.test, got %q", got)
	}

	req2, _ := http.NewRequest("GET", s.URL, nil)
	req2.Header.Set("Origin", "http://evil.test")
	res2, _ := http.DefaultClient.Do(req2)
	if got := res2.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("want no ACAO for evil origin, got %q", got)
	}
}
