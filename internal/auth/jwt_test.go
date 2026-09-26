package auth

import (
	"testing"
	"time"
)

func TestJWT_IssueVerify_OK(t *testing.T) {
	cfg := JWTConfig{
		Secret: []byte("dev-secret-32bytes-please-please!!"),
		Iss:    "go-api-security",
		Aud:    "notes-api",
		Skew:   2 * time.Second,
	}
	tok, err := IssueJWT("alice@example.com", time.Minute, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := VerifyJWT(tok, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if sub != "alice@example.com" {
		t.Fatalf("got sub %q", sub)
	}
}

func TestJWT_Verify_FailsOnWrongAud(t *testing.T) {
	cfg := JWTConfig{
		Secret: []byte("dev-secret-32bytes-please-please!!"),
		Iss:    "go-api-security",
		Aud:    "notes-api",
		Skew:   0,
	}
	tok, err := IssueJWT("alice", time.Minute, cfg)
	if err != nil {
		t.Fatal(err)
	}
	bad := cfg
	bad.Aud = "other"
	if _, err := VerifyJWT(tok, bad); err == nil {
		t.Fatal("expected audience check to fail")
	}
}

func TestJWT_Verify_FailsOnExpiry(t *testing.T) {
	cfg := JWTConfig{
		Secret: []byte("dev-secret-32bytes-please-please!!"),
		Iss:    "go-api-security",
		Aud:    "notes-api",
		Skew:   0,
	}
	tok, err := IssueJWT("alice", time.Millisecond, cfg)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := VerifyJWT(tok, cfg); err == nil {
		t.Fatal("expected expired token to fail")
	}
}
