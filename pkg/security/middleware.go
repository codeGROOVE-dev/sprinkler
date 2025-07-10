package security

import (
	"log"
	"net/http"
	"runtime"
)

// CombinedMiddleware applies all security middleware in one function:
// - Panic recovery
// - Security headers
// - Rate limiting
func CombinedMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Panic recovery
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
			
			// Rate limiting
			ip := GetClientIP(r)
			if !rl.Allow(ip) {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			
			// Security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			
			next.ServeHTTP(w, r)
		})
	}
}