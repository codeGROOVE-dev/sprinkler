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
// - CORS with origin allowlist.
func CombinedMiddleware(rl *RateLimiter, allowedOrigins []string) func(http.Handler) http.Handler {
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
			ip := ClientIP(r)
			if !rl.Allow(ip) {
				log.Printf("rate limit exceeded for IP: %s, path: %s", ip, r.URL.Path)
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			// Security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

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
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				// If origin not allowed, don't set CORS headers (browser will block)
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
