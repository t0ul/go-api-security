package limits

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---- Token-bucket rate limiter (per key) ----

type bucket struct {
	tokens float64
	last   time.Time
}

type Limiter struct {
	mu    sync.Mutex
	bkts  map[string]*bucket
	rate  float64 // tokens per second
	burst float64 // max tokens
	now   func() time.Time
}

func NewLimiter(ratePerSecond float64, burst int) *Limiter {
	return &Limiter{
		bkts:  make(map[string]*bucket),
		rate:  ratePerSecond,
		burst: float64(burst),
		now:   time.Now,
	}
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.bkts[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: l.now()}
		l.bkts[key] = b
	}

	now := l.now()
	elapsed := now.Sub(b.last).Seconds()
	// refill
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens -= 1
		return true
	}
	return false
}

// Key helpers (user first, else client IP).
func KeyUserOrIP(r *http.Request, user string) string {
	if user != "" {
		return "u:" + user
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return "ip:" + strings.TrimSpace(r.RemoteAddr)
	}
	return "ip:" + host
}

// HTTP middleware wrapper.
func RateLimit(lim *Limiter, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if !lim.Allow(key) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
