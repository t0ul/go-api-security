package capstone

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go-api-security/internal/app"

	_ "modernc.org/sqlite"
)

func newDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "capstone.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestCapstone_EndToEnd(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	mux, err := app.BuildGoodMux(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 1) signup
	doJSON(t, "POST", srv.URL+"/demo/signup", `{"email":"amy@example.com","password":"p@ssw0rd"}`, nil)

	// 2) login (JWT)
	var tok struct {
		Token string `json:"token"`
	}
	doJSON(t, "POST", srv.URL+"/auth/login", `{"email":"amy@example.com","password":"p@ssw0rd"}`, &tok)
	if tok.Token == "" {
		t.Fatal("no token")
	}

	// 3) create note (idempotent)
	var note1 map[string]any
	h := hdr{"Authorization": "Bearer " + tok.Token, "Content-Type": "application/json", "Idempotency-Key": "cap-1"}
	doJSONH(t, "POST", srv.URL+"/notes", `{"title":"hello","body":"world"}`, h, &note1)
	id1 := note1["id"]
	if id1 == nil {
		t.Fatalf("missing id: %#v", note1)
	}
	// replay same body + key → same response
	var note1b map[string]any
	doJSONH(t, "POST", srv.URL+"/notes", `{"title":"hello","body":"world"}`, h, &note1b)
	if note1b["id"] != id1 {
		t.Fatal("idempotency replay mismatch")
	}

	// 4) search → should only see own note
	var list []map[string]any
	doGetAuth(t, srv.URL+"/notes?q=hello", tok.Token, &list)
	if len(list) != 1 {
		t.Fatalf("want 1 note, got %d", len(list))
	}

	// 5) register webhook secret
	var reg map[string]string
	doGetPostAuth(t, "POST", srv.URL+"/hooks/register", tok.Token, "", &reg)
	if reg["secret"] == "" {
		t.Fatal("no secret")
	}

	// 6) send signed webhook (OK)
	// ts\nbody signing: compute via small helper in test
	ts := strconvI(time.Now().Unix())
	body := `{"event":"cap","msg":"ok"}`
	sig := hmacHex(reg["secret"], ts+"\n"+body)
	var whOK map[string]any
	doJSONH(t, "POST", srv.URL+"/hooks/ingest/amy@example.com", body, hdr{
		"X-Timestamp": ts, "X-Signature": "sha256=" + sig, "Content-Type": "application/json",
	}, &whOK)
	if whOK["ok"] != true {
		t.Fatalf("webhook not ok: %#v", whOK)
	}

	// 7) SSRF guard blocks localhost
	res, code, _ := raw("GET", srv.URL+"/ssrf/fetch?url=http://127.0.0.1:9999/", "", nil)
	if code == 200 || !strings.Contains(res, "private") {
		t.Fatalf("expected SSRF block, got %d: %s", code, res)
	}

	// 8) audit endpoint returns entries
	var audit []map[string]any
	doGetAuth(t, srv.URL+"/admin/audit?limit=5", tok.Token, &audit)
	if len(audit) == 0 {
		t.Fatal("no audit events recorded")
	}

	// 9) deps endpoint responds
	var deps []map[string]any
	doGetAuth(t, srv.URL+"/admin/deps", tok.Token, &deps)
	if deps == nil {
		t.Fatal("deps nil")
	}
}

/* --- tiny helpers (test-local) --- */

type hdr map[string]string

func raw(method, url, body string, h hdr) (string, int, http.Header) {
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	for k, v := range h {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err.Error(), 0, nil
	}
	defer res.Body.Close()
	b, _ := ioReadAllLimit(res.Body, 1<<20)
	return string(b), res.StatusCode, res.Header
}

func doJSON(t *testing.T, method, url, body string, out any) {
	t.Helper()
	s, code, _ := raw(method, url, body, hdr{"Content-Type": "application/json"})
	if code < 200 || code >= 300 {
		t.Fatalf("%s %s => %d: %s", method, url, code, s)
	}
	if out != nil {
		_ = json.Unmarshal([]byte(s), out)
	}
}

func doJSONH(t *testing.T, method, url, body string, h hdr, out any) {
	t.Helper()
	s, code, _ := raw(method, url, body, h)
	if code < 200 || code >= 300 {
		t.Fatalf("%s %s => %d: %s", method, url, code, s)
	}
	if out != nil {
		_ = json.Unmarshal([]byte(s), out)
	}
}

func doGetAuth(t *testing.T, url, tok string, out any) {
	doJSONH(t, "GET", url, "", hdr{"Authorization": "Bearer " + tok}, out)
}
func doGetPostAuth(t *testing.T, method, url, tok, body string, out any) {
	doJSONH(t, method, url, body, hdr{"Authorization": "Bearer " + tok, "Content-Type": "application/json"}, out)
}

func ioReadAllLimit(r io.Reader, n int64) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, r, n); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf.Bytes(), nil
}

func hmacHex(hexKey, msg string) string {
	key, _ := hex.DecodeString(hexKey)
	sum := hmac.New(sha256.New, key)
	sum.Write([]byte(msg))
	return hex.EncodeToString(sum.Sum(nil))
}

func strconvI(v int64) string { return strconv.FormatInt(v, 10) }
