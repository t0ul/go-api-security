package limits

import (
	"testing"
	"time"
)

func TestLimiter_BurstAndDeny(t *testing.T) {
	lim := NewLimiter(2, 2) // 2 tokens/s, burst 2
	lim.now = func() time.Time { return time.Unix(0, 0) }

	key := "u:alice"
	if !lim.Allow(key) {
		t.Fatal("1 should pass")
	}
	if !lim.Allow(key) {
		t.Fatal("2 should pass (burst)")
	}
	if lim.Allow(key) {
		t.Fatal("3 should be denied (no tokens left)")
	}

	// Advance 0.5s → +1 token
	lim.now = func() time.Time { return time.Unix(0, int64(500*time.Millisecond)) }
	if !lim.Allow(key) {
		t.Fatal("after refill, should pass")
	}
}
