package hmacsig

import (
	"crypto/rand"
	"strconv"
	"testing"
	"time"
)

func randKey(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestComputeVerify_OK(t *testing.T) {
	secret := randKey(t, 32)
	ts := strconvNow()
	body := []byte(`{"event":"demo","value":123}`)
	sig := Compute(secret, ts, body)
	if err := Verify(secret, ts, sig, body, 5*time.Minute); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestVerify_TamperFails(t *testing.T) {
	secret := randKey(t, 32)
	ts := strconvNow()
	body := []byte(`{"event":"demo"}`)
	sig := Compute(secret, ts, body)

	if err := Verify(secret, ts, sig, []byte(`{"event":"pwn"}`), 5*time.Minute); err == nil {
		t.Fatal("expected mismatch to fail")
	}
}

func TestVerify_StaleTimestamp(t *testing.T) {
	secret := randKey(t, 32)
	body := []byte("x")
	// 1970-01-01 too old
	sig := Compute(secret, "1", body)
	if err := Verify(secret, "1", sig, body, time.Minute); err == nil {
		t.Fatal("expected stale timestamp to fail")
	}
}

func strconvNow() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}
