package github

import (
	"sync"
	"time"
)

// TierCache caches tier lookups to reduce API calls to GitHub Marketplace.
// Implements thread-safe in-memory caching with TTL expiration.
//
//nolint:govet // fieldalignment: minimal impact, current order is logical
type TierCache struct {
	mu      sync.RWMutex
	cache   map[string]*tierEntry
	stopCh  chan struct{}
	stopped chan struct{}
	ttl     time.Duration
}

// tierEntry represents a cached tier with expiration.
type tierEntry struct {
	expiresAt time.Time
	tier      Tier
}

// NewTierCache creates a new tier cache with the specified TTL.
// A background goroutine periodically cleans up expired entries.
func NewTierCache(ttl time.Duration) *TierCache {
	tc := &TierCache{
		cache:   make(map[string]*tierEntry),
		ttl:     ttl,
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
	}

	// Start cleanup goroutine
	go tc.cleanupLoop()

	return tc
}

// Get retrieves a tier from the cache.
// Returns (tier, true) if found and not expired, (TierFree, false) otherwise.
func (tc *TierCache) Get(username string) (Tier, bool) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	entry, ok := tc.cache[username]
	if !ok {
		return TierFree, false
	}

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		return TierFree, false
	}

	return entry.tier, true
}

// Set stores a tier in the cache with TTL expiration.
func (tc *TierCache) Set(username string, tier Tier) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.cache[username] = &tierEntry{
		tier:      tier,
		expiresAt: time.Now().Add(tc.ttl),
	}
}

// Stop stops the cleanup goroutine and waits for it to finish.
// Safe to call multiple times (subsequent calls are no-ops).
func (tc *TierCache) Stop() {
	select {
	case <-tc.stopCh:
		// Already stopped
		return
	default:
		close(tc.stopCh)
		<-tc.stopped
	}
}

// cleanupLoop runs periodically to remove expired cache entries.
func (tc *TierCache) cleanupLoop() {
	defer close(tc.stopped)

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-tc.stopCh:
			return
		case <-ticker.C:
			tc.cleanup()
		}
	}
}

// cleanup removes expired entries from the cache.
func (tc *TierCache) cleanup() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	now := time.Now()
	for username, entry := range tc.cache {
		if now.After(entry.expiresAt) {
			delete(tc.cache, username)
		}
	}
}
