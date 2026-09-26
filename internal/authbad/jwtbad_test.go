package authbad

import "testing"

func TestIssueNone_BuildsUnsignedToken(t *testing.T) {
	tok := IssueNone("alice", "iss", "aud", 0)
	if parts := len(split(tok)); parts != 3 {
		t.Fatalf("want 3 parts, got %d", parts)
	}
	if tok[len(tok)-1] != '.' { // ends with dot -> no signature
		t.Fatal("expected empty signature section")
	}
}

func split(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start <= len(s) {
		out = append(out, s[start:])
	}
	return out
}
