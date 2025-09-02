package security

import (
	"log"
	"net/http"
	"runtime"
	"time"
)

// CombinedMiddleware applies all security middleware in one function:
// - Request logging
// - Panic recovery
// - Security headers
// - Rate limiting
// - CORS with origin allowlist.
func CombinedMiddleware(rl *RateLimiter, allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get client IP
			ip := ClientIP(r)

			// Log incoming request
			start := time.Now()
			log.Printf("HTTP request: method=%s path=%s ip=%s user_agent=%q origin=%q",
				r.Method, r.URL.Path, ip, r.UserAgent(), r.Header.Get("Origin"))
			// Wrap ResponseWriter to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Panic recovery
			defer func() {
				if err := recover(); err != nil {
					log.Printf("ERROR: panic recovered: %v, ip=%s, path=%s", err, ip, r.URL.Path)

					// Log stack trace
					buf := make([]byte, 4096)
					n := runtime.Stack(buf, false)
					log.Printf("stack trace:\n%s", buf[:n])

					// Return 500 error
					http.Error(wrapped, "internal server error", http.StatusInternalServerError)
				}

				// Log response details
				duration := time.Since(start)
				if wrapped.statusCode >= 400 {
					// Log errors with more detail
					log.Printf("HTTP response ERROR: status=%d path=%s ip=%s duration=%v user_agent=%q",
						wrapped.statusCode, r.URL.Path, ip, duration, r.UserAgent())
				} else {
					log.Printf("HTTP response: status=%d path=%s ip=%s duration=%v",
						wrapped.statusCode, r.URL.Path, ip, duration)
				}
			}()

			// Rate limiting
			if !rl.Allow(ip) {
				log.Printf("ERROR: rate limit exceeded for IP: %s, path: %s, user_agent: %q", ip, r.URL.Path, r.UserAgent())
				http.Error(wrapped, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			// Security headers
			wrapped.Header().Set("X-Content-Type-Options", "nosniff")
			wrapped.Header().Set("X-Frame-Options", "DENY")
			wrapped.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

			// CORS headers - only allow specific origins from allowlist
			origin := r.Header.Get("Origin")
			if origin != "" && len(allowedOrigins) > 0 {
				// Check if origin is in allowed list
				originAllowed := false
				for _, allowed := range allowedOrigins {
					if origin == allowed {
						originAllowed = true
						break
					}
				}

				if originAllowed {
					wrapped.Header().Set("Access-Control-Allow-Origin", origin)
					wrapped.Header().Set("Access-Control-Allow-Credentials", "true")
				} else {
					// Log CORS rejection
					log.Printf("CORS rejected: origin=%q not in allowed list, ip=%s, path=%s", origin, ip, r.URL.Path)
				}
				// If origin not allowed, don't set CORS headers (browser will block)
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				wrapped.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				wrapped.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				wrapped.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(wrapped, r)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter

	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.written = true
	}
	return rw.ResponseWriter.Write(b)
}
