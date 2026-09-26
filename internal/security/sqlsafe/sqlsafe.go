package sqlsafe

import "strings"

// BuildSearch returns a parameterized SQL statement + args.
// Invariants we test/fuzz:
//  1. Placeholders count == len(args)
//  2. Raw user input never appears in the SQL string
func BuildSearch(owner, q string) (stmt string, args []any) {
	like := "%"
	if q != "" {
		q = strings.Join(strings.Fields(q), " ")
		like = "%" + q + "%"
	}
	stmt = `
SELECT id, owner, title, body, created_at
FROM notes
WHERE owner = ? AND (title LIKE ? OR body LIKE ?)
ORDER BY created_at DESC
LIMIT 50`
	args = []any{owner, like, like}
	return
}
