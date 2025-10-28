// Package security provides security middleware and utilities including
// connection limiting, rate limiting, CORS handling, and GitHub IP validation.
package security

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"sync"
	"time"
)

const (
	staleTimeout       = 10 * time.Minute // Time after which inactive entries are considered stale
	maxIPEntries       = 10000            // Maximum number of IP entries to prevent memory exhaustion
	reservationTimeout = 10 * time.Second // Time before unused reservations expire
)

// connectionInfo tracks connection count and last activity time.
type connectionInfo struct {
	lastActive   time.Time
	count        int
	reservations int // Pending reservations (not yet committed)
}

// reservation represents a reserved connection slot.
type reservation struct {
	createdAt time.Time
	ip        string
}

// ConnectionLimiter tracks connections per IP and total.
type ConnectionLimiter struct {
	perIP        map[string]*connectionInfo
	reservations map[string]*reservation // token -> reservation
	stopCleanup  chan struct{}
	total        int
	totalReserve int // Total reserved (pending) connections
	maxPerIP     int
	maxTotal     int
	mu           sync.Mutex
}

// NewConnectionLimiter creates a new connection limiter with periodic cleanup.
func NewConnectionLimiter(maxPerIP, maxTotal int) *ConnectionLimiter {
	cl := &ConnectionLimiter{
		perIP:        make(map[string]*connectionInfo),
		reservations: make(map[string]*reservation),
		maxPerIP:     maxPerIP,
		maxTotal:     maxTotal,
		stopCleanup:  make(chan struct{}),
	}

	// Start cleanup goroutine to remove stale entries
	go cl.cleanupLoop()

	return cl
}

// Reserve reserves a connection slot for the given IP, returning a token.
// Returns empty string if the limit would be exceeded.
// The reservation must be committed with CommitReservation() or it will expire.
func (cl *ConnectionLimiter) Reserve(ip string) string {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	// Check if we would exceed limits (including reservations)
	info := cl.perIP[ip]
	perIPTotal := 0
	if info != nil {
		perIPTotal = info.count + info.reservations
	}

	if cl.total+cl.totalReserve >= cl.maxTotal || perIPTotal >= cl.maxPerIP {
		return ""
	}

	// Generate secure random token
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		log.Printf("ERROR: failed to generate reservation token: %v", err)
		return ""
	}
	token := hex.EncodeToString(tokenBytes)

	// Create or update connection info
	if info == nil {
		// Check memory limit before creating new entry
		if len(cl.perIP) >= maxIPEntries {
			cl.evictOldestInactive()
			if len(cl.perIP) >= maxIPEntries {
				return ""
			}
		}
		info = &connectionInfo{}
		cl.perIP[ip] = info
	}

	// Record reservation
	cl.reservations[token] = &reservation{
		ip:        ip,
		createdAt: time.Now(),
	}
	info.reservations++
	info.lastActive = time.Now()
	cl.totalReserve++

	return token
}

// CommitReservation converts a reservation into an active connection.
// Returns false if the token is invalid or expired.
func (cl *ConnectionLimiter) CommitReservation(token string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	res := cl.reservations[token]
	if res == nil {
		return false
	}

	// Check if reservation expired
	if time.Since(res.createdAt) > reservationTimeout {
		// Clean up expired reservation
		delete(cl.reservations, token)
		if info := cl.perIP[res.ip]; info != nil {
			info.reservations--
			if info.reservations < 0 {
				info.reservations = 0
			}
		}
		cl.totalReserve--
		if cl.totalReserve < 0 {
			cl.totalReserve = 0
		}
		return false
	}

	info := cl.perIP[res.ip]
	if info == nil {
		// This shouldn't happen, but handle gracefully
		delete(cl.reservations, token)
		cl.totalReserve--
		return false
	}

	// Convert reservation to active connection
	info.count++
	info.reservations--
	info.lastActive = time.Now()
	cl.total++
	cl.totalReserve--
	delete(cl.reservations, token)

	return true
}

// CancelReservation cancels a reservation without converting it to a connection.
func (cl *ConnectionLimiter) CancelReservation(token string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	res := cl.reservations[token]
	if res == nil {
		return
	}

	// Remove reservation
	delete(cl.reservations, token)
	if info := cl.perIP[res.ip]; info != nil {
		info.reservations--
		info.lastActive = time.Now()
		if info.reservations < 0 {
			info.reservations = 0
		}
		// Clean up if no connections and no reservations
		if info.count == 0 && info.reservations == 0 {
			delete(cl.perIP, res.ip)
		}
	}
	cl.totalReserve--
	if cl.totalReserve < 0 {
		cl.totalReserve = 0
	}
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

// cleanup removes entries that haven't been active and expired reservations.
func (cl *ConnectionLimiter) cleanup() {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	now := time.Now()
	cleaned := 0
	expiredReservations := 0

	// Clean up stale IP entries
	for ip, info := range cl.perIP {
		if info.count == 0 && info.reservations == 0 && now.Sub(info.lastActive) > staleTimeout {
			delete(cl.perIP, ip)
			cleaned++
		}
	}

	// Clean up expired reservations
	for token, res := range cl.reservations {
		if now.Sub(res.createdAt) > reservationTimeout {
			delete(cl.reservations, token)
			if info := cl.perIP[res.ip]; info != nil {
				info.reservations--
				if info.reservations < 0 {
					info.reservations = 0
				}
			}
			cl.totalReserve--
			expiredReservations++
		}
	}

	if cleaned > 0 || expiredReservations > 0 {
		log.Printf("ConnectionLimiter: cleaned up %d stale IPs, %d expired reservations", cleaned, expiredReservations)
	}

	// Sanity check on totalReserve
	if cl.totalReserve < 0 {
		log.Printf("ConnectionLimiter: WARN: totalReserve was negative (%d), resetting to 0", cl.totalReserve)
		cl.totalReserve = 0
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
