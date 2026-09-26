package crypto

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

func TestBcrypt_RoundTrip(t *testing.T) {
	h, err := HashPassword("p@ssw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPassword(h, "p@ssw0rd!"); err != nil {
		t.Fatalf("expected password to verify: %v", err)
	}
	if err := CheckPassword(h, "wrong"); err == nil {
		t.Fatalf("expected wrong password to fail")
	}
}

func TestGCM_EncryptDecrypt_RoundTrip_AndRandomNonce(t *testing.T) {
	key := randKey(t, 32)
	plain := []byte("hello world")

	c1, n1, err := Encrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	c2, n2, err := Encrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}

	// Nonces must differ → ciphertexts must differ
	if bytes.Equal(n1, n2) {
		t.Fatalf("nonces should differ")
	}
	if bytes.Equal(c1, c2) {
		t.Fatalf("ciphertexts should differ due to fresh nonce")
	}

	p1, err := Decrypt(key, n1, c1)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Decrypt(key, n2, c2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(p1, plain) || !bytes.Equal(p2, plain) {
		t.Fatalf("decrypt did not recover original")
	}

	// Wrong key should fail
	wrong := randKey(t, 32)
	if _, err := Decrypt(wrong, n1, c1); err == nil {
		t.Fatalf("decrypt with wrong key should fail")
	}
}
