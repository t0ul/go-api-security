package limits

import (
	"testing"
	"time"
)

func TestIdStore_BasicSetGetTTL(t *testing.T) {
	s := NewIdStore(50 * time.Millisecond)
	s.now = func() time.Time { return time.Unix(0, 0) }

	key := "u:alice|POST|/notes|demo"
	ent := Entry{Status: 201, Body: []byte(`{"id":1}`), BodyHash: "x", Type: "application/json", ExpiresAt: s.now().Add(s.ttl)}
	s.Set(key, ent)

	if got, ok := s.Get(key); !ok || got.Status != 201 || string(got.Body) != `{"id":1}` {
		t.Fatalf("get mismatch: %#v %#v", ok, got)
	}

	// expire it
	s.now = func() time.Time { return time.Unix(0, int64(100*time.Millisecond)) }
	if _, ok := s.Get(key); ok {
		t.Fatalf("expected expired entry to be gone")
	}
}
