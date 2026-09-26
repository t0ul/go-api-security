package urlguard

import "testing"

// Quick invariant: never panic; only http/https accepted when parse succeeds.
func FuzzParseAndValidate(f *testing.F) {
	seeds := []string{
		"http://example.com",
		"https://example.com/a?b=c",
		"http://127.0.0.1/",
		"file:///etc/passwd",
		"mailto:foo@bar",
		"::::",
		"https://user@example.com/",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := ParseAndValidate(s)
		if err == nil {
			if u.Scheme != "http" && u.Scheme != "https" {
				t.Fatalf("unexpected scheme %q", u.Scheme)
			}
		}
	})
}
