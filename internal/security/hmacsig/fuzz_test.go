package hmacsig

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

func FuzzVerify(f *testing.F) {
	// seed with a valid combo
	sec := make([]byte, 32)
	_, _ = rand.Read(sec)
	secret := hex.EncodeToString(sec)
	ts := strconvNow()
	body := []byte(`{"x":1}`)
	sig := Compute(sec, ts, body)
	f.Add(secret, ts, string(body), sig)

	f.Fuzz(func(t *testing.T, hexKey, ts, body, sig string) {
		key, _ := hex.DecodeString(hexKey)
		_ = Verify(key, ts, sig, []byte(body), 5*time.Minute)
	})
}
