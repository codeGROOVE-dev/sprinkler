package security

import "sync"

// ConnectionLimiter tracks connections per IP and total.
type ConnectionLimiter struct {
	mu       sync.Mutex
	perIP    map[string]int
	total    int
	maxPerIP int
	maxTotal int
}

// NewConnectionLimiter creates a new connection limiter.
func NewConnectionLimiter(maxPerIP, maxTotal int) *ConnectionLimiter {
	return &ConnectionLimiter{
		perIP:    make(map[string]int),
		maxPerIP: maxPerIP,
		maxTotal: maxTotal,
	}
}

// Add attempts to add a connection for the given IP.
func (cl *ConnectionLimiter) Add(ip string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.total >= cl.maxTotal || cl.perIP[ip] >= cl.maxPerIP {
		return false
	}

	cl.perIP[ip]++
	cl.total++
	return true
}

// Remove removes a connection for the given IP.
func (cl *ConnectionLimiter) Remove(ip string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if count := cl.perIP[ip]; count > 0 {
		if count == 1 {
			delete(cl.perIP, ip)
		} else {
			cl.perIP[ip]--
		}
		cl.total--
	}
}