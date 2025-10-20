package security

import (
	"sync"
	"time"
)

const (
	maxBuckets = 10000 // Limit to 10k unique IPs to prevent memory exhaustion
)

// RateLimiter implements a simple token bucket rate limiter.
type RateLimiter struct {
	buckets    map[string]*bucket
	stopCh     chan struct{}
	cleanupWG  sync.WaitGroup
	maxTokens  int
	maxBuckets int
	mu         sync.Mutex
}

type bucket struct {
	resetTime time.Time
	count     int
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(maxTokens int) *RateLimiter {
	rl := &RateLimiter{
		buckets:    make(map[string]*bucket),
		maxTokens:  maxTokens,
		maxBuckets: maxBuckets,
		stopCh:     make(chan struct{}),
	}

	// Start cleanup goroutine
	rl.cleanupWG.Add(1)
	go rl.cleanupRoutine()

	return rl
}

// Allow checks if a request from the given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, exists := rl.buckets[ip]

	// Create new bucket or reset if expired
	if !exists || now.After(b.resetTime) {
		// Check if we've reached the max buckets limit
		if !exists && len(rl.buckets) >= rl.maxBuckets {
			// Find and remove the oldest bucket to make room
			rl.evictOldest()
		}

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

// cleanupRoutine periodically removes expired buckets to prevent memory leaks.
func (rl *RateLimiter) cleanupRoutine() {
	defer rl.cleanupWG.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopCh:
			return
		}
	}
}

// cleanup removes expired buckets.
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, b := range rl.buckets {
		if now.After(b.resetTime) {
			delete(rl.buckets, ip)
		}
	}
}

// evictOldest removes the oldest bucket (called with lock held).
func (rl *RateLimiter) evictOldest() {
	var oldestIP string
	var oldestTime time.Time

	// Find the oldest bucket
	for ip, b := range rl.buckets {
		if oldestIP == "" || b.resetTime.Before(oldestTime) {
			oldestIP = ip
			oldestTime = b.resetTime
		}
	}

	if oldestIP != "" {
		delete(rl.buckets, oldestIP)
	}
}

// Stop gracefully stops the rate limiter.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
	rl.cleanupWG.Wait()
}
