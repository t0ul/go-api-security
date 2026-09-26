package deps

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		A, B string
		Want int
	}{
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.10.0", "1.2.99", 1},
		{"1.2", "1.2.0", 0},
		{"1.2.3+meta", "1.2.3", 0},
	}
	for _, c := range cases {
		if got := Compare(c.A, c.B); got != c.Want {
			t.Fatalf("%s vs %s: got %d want %d", c.A, c.B, got, c.Want)
		}
	}
}
