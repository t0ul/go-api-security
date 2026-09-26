package sqlsafe

//
//import (
//	"strings"
//	"testing"
//)
//
//func countQ(s string) int {
//	c := 0
//	for i := range s {
//		if s[i] == '?' {
//			c++
//		}
//	}
//	return c
//}
//
//func FuzzBuildSearch(f *testing.T) {
//	f.Add("alice", "hello")
//	f.Add("bob", "bob' OR 1=1 --")
//	f.Add("carol", "")
//	f.Add("dave", "%_wild_%")
//
//	f.Fuzz(func(t *testing.T, owner, q string) {
//		stmt, args := BuildSearch(owner, q)
//		if stmt == "" || len(args) != 3 {
//			t.Fatalf("bad build: args=%d", len(args))
//		}
//		if got := countQ(stmt); got != len(args) {
//			t.Fatalf("placeholders=%d args=%d", got, len(args))
//		}
//		if strings.Contains(stmt, owner) || strings.Contains(stmt, q) {
//			t.Fatalf("user input leaked into SQL text")
//		}
//	})
//}
