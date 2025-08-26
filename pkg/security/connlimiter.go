// Package security provides security middleware and utilities including
// connection limiting, rate limiting, CORS handling, and GitHub IP validation.
package security

import (
	"log"
	"sync"
	"time"
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

// Add attempts to add a connection for the given IP.
func (cl *ConnectionLimiter) Add(ip string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	info := cl.perIP[ip]
	if info == nil {
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
	staleTimeout := 10 * time.Minute
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

// Stop gracefully stops the cleanup goroutine.
func (cl *ConnectionLimiter) Stop() {
	close(cl.stopCleanup)
}
