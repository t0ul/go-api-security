package sqlbad

import "strings"

// BuildSearch BAD: constructs SQL via string concatenation.
// This is intentionally vulnerable to injection.
func BuildSearch(owner, q string) string {
	// try to look "careful" but it's still unsafe:
	q = strings.ReplaceAll(q, "\n", " ")
	return "SELECT id, owner, title, body, created_at FROM notes " +
		"WHERE owner = '" + owner + "' AND (title LIKE '%" + q + "%' OR body LIKE '%" + q + "%') " +
		"ORDER BY created_at DESC LIMIT 50"
}
