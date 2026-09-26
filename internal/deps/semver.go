package deps

import "strings"

// Compare returns -1 if a<b, 0 if equal, +1 if a>b (SemVer-ish, tolerant).
// Accepts optional "v" prefix; ignores build metadata (+foo).
func Compare(a, b string) int {
	trim := func(s string) string {
		if strings.HasPrefix(s, "v") {
			s = s[1:]
		}
		if i := strings.IndexByte(s, '+'); i >= 0 {
			s = s[:i]
		}
		return s
	}
	a, b = trim(a), trim(b)
	as := strings.SplitN(a, "-", 2)[0]
	bs := strings.SplitN(b, "-", 2)[0]

	ap := strings.Split(as, ".")
	bp := strings.Split(bs, ".")
	// pad to 3 (major.minor.patch)
	for len(ap) < 3 {
		ap = append(ap, "0")
	}
	for len(bp) < 3 {
		bp = append(bp, "0")
	}

	toInt := func(s string) int {
		n := 0
		for i := 0; i < len(s); i++ {
			c := s[i] - '0'
			if c > 9 {
				break
			}
			n = n*10 + int(c)
		}
		return n
	}
	for i := 0; i < 3; i++ {
		ai, bi := toInt(ap[i]), toInt(bp[i])
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}
