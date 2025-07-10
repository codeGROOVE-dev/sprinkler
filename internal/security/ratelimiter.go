package security

import (
	"sync"
	"time"
)

// RateLimiter implements a simple token bucket rate limiter.
type RateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	maxTokens int
}

type bucket struct {
	count     int
	resetTime time.Time
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(maxTokens int, _ time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets:   make(map[string]*bucket),
		maxTokens: maxTokens,
	}
}

// Allow checks if a request from the given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, exists := rl.buckets[ip]

	// Create new bucket or reset if expired
	if !exists || now.After(b.resetTime) {
		rl.buckets[ip] = &bucket{
			count:     1,
			resetTime: now.Add(time.Minute),
		}
		return true
	}

	// Check limit
	if b.count >= rl.maxTokens {
		return false
	}

	b.count++
	return true
}

