package cryptobad

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func randKey(t *testing.T, n int) []byte {
	t.Helper()
	k := make([]byte, n)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestPlaintextStorage_AllowsDirectExposure(t *testing.T) {
	stored := StorePlain("hunter2")
	// ❌ Demonstrates why plaintext storage is terrible:
	// a breach yields the exact credential.
	if stored != "hunter2" {
		t.Fatalf("expected plaintext to be stored as-is")
	}
}

func TestFixedNonce_ProducesIdenticalCiphertext(t *testing.T) {
	key := randKey(t, 32)
	plain := []byte("same message")
	c1, err := InsecureEncryptGCMFixedNonce(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := InsecureEncryptGCMFixedNonce(key, plain)
	if err != nil {
		t.Fatal(err)
	}

	// ❌ Catastrophic: same nonce ⇒ same ciphertext for same plaintext.
	if !bytes.Equal(c1, c2) {
		t.Fatalf("expected identical ciphertext with fixed nonce")
	}
}
