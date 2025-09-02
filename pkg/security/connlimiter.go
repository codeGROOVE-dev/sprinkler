// Package security provides security middleware and utilities including
// connection limiting, rate limiting, CORS handling, and GitHub IP validation.
package security

import (
	"log"
	"sync"
	"time"
)

const (
	staleTimeout = 10 * time.Minute // Time after which inactive entries are considered stale
	maxIPEntries = 10000            // Maximum number of IP entries to prevent memory exhaustion
)

// connectionInfo tracks connection count and last activity time.
type connectionInfo struct {
	lastActive time.Time
	count      int
}

// ConnectionLimiter tracks connections per IP and total.
type ConnectionLimiter struct {
	perIP       map[string]*connectionInfo
	stopCleanup chan struct{}
	total       int
	maxPerIP    int
	maxTotal    int
	mu          sync.Mutex
}

// NewConnectionLimiter creates a new connection limiter with periodic cleanup.
func NewConnectionLimiter(maxPerIP, maxTotal int) *ConnectionLimiter {
	cl := &ConnectionLimiter{
		perIP:       make(map[string]*connectionInfo),
		maxPerIP:    maxPerIP,
		maxTotal:    maxTotal,
		stopCleanup: make(chan struct{}),
	}

	// Start cleanup goroutine to remove stale entries
	go cl.cleanupLoop()

	return cl
}

// CanAdd checks if a connection can be added for the given IP without actually adding it.
func (cl *ConnectionLimiter) CanAdd(ip string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.total >= cl.maxTotal {
		return false
	}

	if info := cl.perIP[ip]; info != nil && info.count >= cl.maxPerIP {
		return false
	}

	// Check if we would hit the IP entry limit
	if _, exists := cl.perIP[ip]; !exists && len(cl.perIP) >= maxIPEntries {
		// Would need to evict, but might not be able to
		hasInactive := false
		for _, info := range cl.perIP {
			if info.count == 0 {
				hasInactive = true
				break
			}
		}
		if !hasInactive {
			return false
		}
	}

	return true
}

// Add attempts to add a connection for the given IP.
func (cl *ConnectionLimiter) Add(ip string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	info := cl.perIP[ip]
	if info == nil {
		// Prevent memory exhaustion by limiting total IP entries
		if len(cl.perIP) >= maxIPEntries {
			// Find and remove the oldest inactive entry to make room
			cl.evictOldestInactive()
			// If still at limit after eviction, deny the connection
			if len(cl.perIP) >= maxIPEntries {
				return false
			}
		}
		info = &connectionInfo{}
		cl.perIP[ip] = info
	}

	if cl.total >= cl.maxTotal || info.count >= cl.maxPerIP {
		return false
	}

	info.count++
	info.lastActive = time.Now()
	cl.total++
	return true
}

// Remove removes a connection for the given IP.
func (cl *ConnectionLimiter) Remove(ip string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if info := cl.perIP[ip]; info != nil && info.count > 0 {
		info.count--
		info.lastActive = time.Now()
		cl.total--

		// Remove entry if no more connections
		if info.count == 0 {
			delete(cl.perIP, ip)
		}
	}
}

// cleanupLoop periodically removes stale entries.
func (cl *ConnectionLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cl.cleanup()
		case <-cl.stopCleanup:
			return
		}
	}
}

// cleanup removes entries that haven't been active for over 10 minutes.
func (cl *ConnectionLimiter) cleanup() {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	now := time.Now()
	// Use the constant defined at package level
	cleaned := 0

	for ip, info := range cl.perIP {
		if info.count == 0 && now.Sub(info.lastActive) > staleTimeout {
			delete(cl.perIP, ip)
			cleaned++
		}
	}

	if cleaned > 0 {
		log.Printf("ConnectionLimiter: cleaned up %d stale IP entries", cleaned)
	}
}

// evictOldestInactive removes the oldest inactive entry (must be called with lock held).
func (cl *ConnectionLimiter) evictOldestInactive() {
	var oldestIP string
	var oldestTime time.Time

	// Find the oldest inactive entry
	for ip, info := range cl.perIP {
		if info.count == 0 && (oldestIP == "" || info.lastActive.Before(oldestTime)) {
			oldestIP = ip
			oldestTime = info.lastActive
		}
	}

	if oldestIP != "" {
		delete(cl.perIP, oldestIP)
	}
}

// Stop gracefully stops the cleanup goroutine.
func (cl *ConnectionLimiter) Stop() {
	close(cl.stopCleanup)
}
