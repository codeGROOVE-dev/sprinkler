package main

import (
	"log"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"
)

// rateLimiter implements a simple token bucket rate limiter.
type rateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	maxTokens int
}

type bucket struct {
	count     int
	resetTime time.Time
}

// newRateLimiter creates a new rate limiter.
func newRateLimiter(maxTokens int, _ time.Duration) *rateLimiter {
	return &rateLimiter{
		buckets:   make(map[string]*bucket),
		maxTokens: maxTokens,
	}
}

// allow checks if a request from the given IP is allowed.
func (rl *rateLimiter) allow(ip string) bool {
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


// connectionLimiter tracks connections per IP and total.
type connectionLimiter struct {
	mu       sync.Mutex
	perIP    map[string]int
	total    int
	maxPerIP int
	maxTotal int
}

// newConnectionLimiter creates a new connection limiter.
func newConnectionLimiter(maxPerIP, maxTotal int) *connectionLimiter {
	return &connectionLimiter{
		perIP:    make(map[string]int),
		maxPerIP: maxPerIP,
		maxTotal: maxTotal,
	}
}

// add attempts to add a connection for the given IP.
func (cl *connectionLimiter) add(ip string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.total >= cl.maxTotal || cl.perIP[ip] >= cl.maxPerIP {
		return false
	}

	cl.perIP[ip]++
	cl.total++
	return true
}

// remove removes a connection for the given IP.
func (cl *connectionLimiter) remove(ip string) {
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

// getClientIP extracts the client IP from the request.
// We only use RemoteAddr to avoid header spoofing.
func getClientIP(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// securityMiddleware adds essential security headers to responses.
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware applies rate limiting to HTTP requests.
func rateLimitMiddleware(rl *rateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		if !rl.allow(ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// recoverMiddleware recovers from panics and prevents server crashes.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic recovered: %v", err)
				
				// Log stack trace
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				log.Printf("stack trace:\n%s", buf[:n])
				
				// Return 500 error
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		
		next.ServeHTTP(w, r)
	})
}


// validateSubscription performs security validation on subscription data.
func validateSubscription(sub *Subscription) error {
	// Validate username
	if sub.Username != "" {
		if len(sub.Username) > 39 { // GitHub username max length
			return errInvalidUsername
		}
		// GitHub usernames can only contain alphanumeric characters and hyphens
		for _, c := range sub.Username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return errInvalidUsername
			}
		}
	}

	// Validate PR URL
	if sub.PRURL != "" {
		if len(sub.PRURL) > 500 || !strings.HasPrefix(sub.PRURL, "https://github.com/") {
			return errInvalidURL
		}
		// Check for path traversal
		if strings.Contains(sub.PRURL, "..") || strings.Contains(sub.PRURL[19:], "//") {
			return errInvalidURL
		}
	}

	// Validate repository URL
	if sub.Repository != "" {
		if len(sub.Repository) > 500 || !strings.HasPrefix(sub.Repository, "https://github.com/") {
			return errInvalidURL
		}
		// Check for path traversal
		if strings.Contains(sub.Repository, "..") || strings.Contains(sub.Repository[19:], "//") {
			return errInvalidURL
		}
	}

	return nil
}