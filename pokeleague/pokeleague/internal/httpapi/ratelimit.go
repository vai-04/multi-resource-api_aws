package httpapi

import (
	"context"
	"math"
	"strconv"
	"sync"
	"time"
)

// limiter is a per-key token bucket: each key gets `burst` tokens that refill
// at `rate` per second. It protects credential endpoints from brute force.
//
// It is in-memory, so with N replicas a client gets N x the limit. That's an
// acceptable first layer; the durable answer is AWS WAF rate-based rules in
// front of the load balancer, or a shared store such as ElastiCache.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute int, burst int) *limiter {
	return &limiter{
		buckets: map[string]*bucket{},
		rate:    float64(perMinute) / 60,
		burst:   float64(burst),
		now:     time.Now,
	}
}

// allow consumes one token for key. When none is available it returns how
// long until one will be.
func (l *limiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// janitor evicts idle buckets so memory doesn't grow with every IP ever seen.
func (l *limiter) janitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.mu.Lock()
			full := time.Duration(l.burst / l.rate * float64(time.Second))
			for k, b := range l.buckets {
				if l.now().Sub(b.last) > full { // would have refilled completely
					delete(l.buckets, k)
				}
			}
			l.mu.Unlock()
		}
	}
}

func retryAfterSeconds(d time.Duration) string {
	return strconv.Itoa(max(1, int(math.Ceil(d.Seconds()))))
}
