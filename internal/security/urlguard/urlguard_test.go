package urlguard

import (
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip   string
		priv bool
	}{
		{"127.0.0.1", true},
		{"10.1.2.3", true},
		{"172.31.255.1", true},
		{"192.168.1.1", true},
		{"169.254.10.20", true},
		{"100.64.1.2", true},
		{"8.8.8.8", false},
		{"::1", true},
		{"fe80::1", true},
		{"fc00::1", true},
		{"2607:f8b0:4005:805::200e", false},
	}
	for _, c := range cases {
		if got := IsPrivateIP(net.ParseIP(c.ip)); got != c.priv {
			t.Fatalf("%s expected %v got %v", c.ip, c.priv, got)
		}
	}
}

func TestParseAndValidate(t *testing.T) {
	if _, err := ParseAndValidate("file:///etc/passwd"); err == nil {
		t.Fatal("expected file scheme rejected")
	}
	if _, err := ParseAndValidate("https://user@host/"); err == nil {
		t.Fatal("expected userinfo rejected")
	}
	u, err := ParseAndValidate("https://example.com/path")
	if err != nil || u.Host != "example.com" {
		t.Fatalf("unexpected parse: %v %v", u, err)
	}
}

func TestHostAllowed(t *testing.T) {
	a := []string{"example.com", "allowed.test"}
	if !hostAllowed("api.example.com", a) || !hostAllowed("allowed.test", a) {
		t.Fatal("should allow subdomain and exact")
	}
	if hostAllowed("evil.com", a) {
		t.Fatal("should block")
	}
}
