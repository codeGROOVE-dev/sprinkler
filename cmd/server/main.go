// Package main implements githooksock, a GitHub webhook listener that provides
// WebSocket subscriptions for pull request events to interested clients.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/websocket"

	"github.com/codeGROOVE-dev/sprinkler/pkg/security"
	"github.com/codeGROOVE-dev/sprinkler/pkg/srv"
	"github.com/codeGROOVE-dev/sprinkler/pkg/webhook"
)

const (
	readTimeout         = 10 * time.Second
	writeTimeout        = 10 * time.Second
	idleTimeout         = 120 * time.Second
	maxHeaderBytes      = 20  // Max header size multiplier (1 << 20 = 1MB)
	minTokenLength      = 40  // Minimum GitHub token length
	maxTokenLength      = 255 // Maximum GitHub token length
	minMaskHeaderLength = 20  // Minimum header length before we show full "[REDACTED]"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	reservationTokenKey contextKey = "reservation_token"
	userAgentKey        contextKey = "user_agent"
)

var (
	webhookSecret = flag.String("webhook-secret", os.Getenv("GITHUB_WEBHOOK_SECRET"), "GitHub webhook secret for signature verification")
	addr          = flag.String("addr", ":8080", "HTTP service address")
	letsencrypt   = flag.Bool("letsencrypt", false, "Use Let's Encrypt for automatic TLS certificates")
	leDomains     = flag.String("le-domains", "", "Comma-separated list of domains for Let's Encrypt certificates")
	leCacheDir    = flag.String("le-cache-dir", "./.letsencrypt", "Cache directory for Let's Encrypt certificates")
	leEmail       = flag.String("le-email", "", "Contact email for Let's Encrypt notifications")
	maxConnsPerIP = flag.Int("max-conns-per-ip", 10, "Maximum WebSocket connections per IP")
	maxConnsTotal = flag.Int("max-conns-total", 1000, "Maximum total WebSocket connections")
	allowedEvents = flag.String("allowed-events", func() string {
		if value := os.Getenv("ALLOWED_WEBHOOK_EVENTS"); value != "" {
			return value
		}
		return "*"
	}(), "Comma-separated list of allowed webhook event types (use '*' for all, default: '*')")
	debugHeaders = flag.Bool("debug-headers", false, "Log request headers for debugging (security warning: may log sensitive data)")
	enforceTiers = flag.Bool("enforce-tiers", func() bool {
		if val := os.Getenv("ENFORCE_TIERS"); val != "" {
			return val == "true" || val == "1"
		}
		return false
	}(), "Enforce GitHub Marketplace tier restrictions (default: false, logs warnings only; can set via ENFORCE_TIERS env)")
)

//nolint:funlen,gocognit,lll,revive,maintidx // Main function orchestrates entire server setup and cannot be split without losing clarity
func main() {
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())

	// Get webhook secret from flag or environment variable
	webhookSecretValue := *webhookSecret

	// Validate webhook secret is configured (REQUIRED for security)
	if webhookSecretValue == "" {
		cancel()
		log.Fatal("ERROR: Webhook secret is required for security. Set -webhook-secret or GITHUB_WEBHOOK_SECRET environment variable.")
	}

	// Parse allowed events
	var allowedEventTypes []string
	if *allowedEvents == "*" {
		log.Println("Allowing all webhook event types")
		allowedEventTypes = nil // nil means allow all
	} else {
		allowedEventTypes = strings.Split(*allowedEvents, ",")
		for i := range allowedEventTypes {
			allowedEventTypes[i] = strings.TrimSpace(allowedEventTypes[i])
		}
		log.Printf("Allowing webhook event types: %v", allowedEventTypes)
	}

	// Defer cancel after all fatal validations
	defer cancel()

	// CORS support removed - WebSocket clients should handle auth via Authorization header

	hub := srv.NewHub(*enforceTiers)
	go hub.Run(ctx)

	if *enforceTiers {
		log.Println("Tier enforcement ENABLED - private repo access restricted to Pro/Flock tiers")
	} else {
		log.Println("Tier enforcement DISABLED - will log warnings only (all users can access private repos)")
	}

	// Create connection limiter for WebSocket connections
	connLimiter := security.NewConnectionLimiter(*maxConnsPerIP, *maxConnsTotal)

	mux := http.NewServeMux()

	// Health check endpoint - exact match only
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip := security.ClientIP(r)

		// Only respond OK to exact root path
		if r.URL.Path == "/" {
			// Don't log health checks to reduce noise
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("webhook-sprinkler is running\n")); err != nil {
				log.Printf("failed to write health check response: %v", err)
			}
			return
		}
		// Return 404 for any other path
		log.Printf("404 Not Found: path=%s ip=%s", r.URL.Path, ip)
		http.NotFound(w, r)
	})
	log.Println("Registered health check handler at /")

	// Webhook handler - exact match
	webhookHandler := webhook.NewHandler(hub, webhookSecretValue, allowedEventTypes)
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		ip := security.ClientIP(r)
		startTime := time.Now()

		// Log request
		log.Printf("Webhook request: path=%s ip=%s method=%s", r.URL.Path, ip, r.Method)

		// Exact path match only
		if r.URL.Path != "/webhook" {
			http.NotFound(w, r)
			return
		}

		webhookHandler.ServeHTTP(w, r)
		log.Printf("Webhook complete: ip=%s duration=%v", ip, time.Since(startTime))
	})
	log.Println("Registered webhook handler at /webhook")

	// WebSocket handler - exact match
	wsHandler := srv.NewWebSocketHandler(hub, connLimiter, allowedEventTypes)
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		ip := security.ClientIP(r)

		// Log request start
		log.Printf("WebSocket request START: path=%s ip=%s user_agent=%s",
			r.URL.Path, ip, r.UserAgent())

		// Only log headers if debug flag is set
		if *debugHeaders {
			log.Print("DEBUG: Headers logging enabled (security warning)")
			for name, values := range r.Header {
				for _, value := range values {
					// Mask sensitive headers even in debug mode
					switch strings.ToLower(name) {
					case "authorization", "x-hub-signature-256", "cookie", "x-api-key":
						if len(value) > 10 {
							log.Printf("WebSocket header: %s: [REDACTED len=%d]", name, len(value))
						} else {
							log.Printf("WebSocket header: %s: [REDACTED]", name)
						}
					default:
						log.Printf("WebSocket header: %s: %s", name, value)
					}
				}
			}
		}

		// Exact path match only
		if r.URL.Path != "/ws" {
			log.Printf("WebSocket 404: wrong path=%s ip=%s", r.URL.Path, ip)
			http.NotFound(w, r)
			return
		}

		// Validate User-Agent header format
		userAgent, err := security.ParseUserAgent(r)
		if err != nil {
			log.Printf("WebSocket 400: invalid user-agent ip=%s error=%q user_agent=%q",
				ip, err.Error(), r.UserAgent())
			w.WriteHeader(http.StatusBadRequest)
			msg := fmt.Sprintf("400 Bad Request: %s\n", err.Error())
			if _, writeErr := w.Write([]byte(msg)); writeErr != nil {
				log.Printf("failed to write 400 response: %v", writeErr)
			}
			return
		}

		// Store parsed User-Agent in context for handler to use
		r = r.WithContext(context.WithValue(r.Context(), userAgentKey, userAgent))

		// Pre-validate authentication before WebSocket upgrade
		authHeader := r.Header.Get("Authorization")
		if !wsHandler.PreValidateAuth(r) {
			// Determine specific failure reason for better debugging
			reason := "missing"
			if authHeader != "" {
				if !strings.HasPrefix(authHeader, "Bearer ") {
					reason = "invalid_format"
				} else {
					token := strings.TrimPrefix(authHeader, "Bearer ")
					if len(token) < minTokenLength || len(token) > maxTokenLength {
						reason = fmt.Sprintf("invalid_length_%d", len(token))
					} else {
						reason = "invalid_pattern"
					}
				}
			}

			// Mask token for security (show only length if present)
			authHeaderLog := "missing"
			if authHeader != "" {
				if len(authHeader) > minMaskHeaderLength {
					authHeaderLog = fmt.Sprintf("Bearer [REDACTED len=%d]", len(authHeader)-7)
				} else {
					authHeaderLog = "[REDACTED]"
				}
			}

			log.Printf("WebSocket 403: auth failed ip=%s reason=%s auth_header=%q", ip, reason, authHeaderLog)
			w.WriteHeader(http.StatusForbidden)
			msg := "403 Forbidden: Invalid or missing GitHub token. " +
				"Please provide a valid token in the Authorization header as 'Bearer <token>'\n"
			if _, err := w.Write([]byte(msg)); err != nil {
				log.Printf("failed to write 403 response: %v", err)
			}
			return
		}

		// Reserve a connection slot before upgrade (prevents TOCTOU race condition)
		reservationToken := connLimiter.Reserve(ip)
		if reservationToken == "" {
			log.Printf("WebSocket 429: connection limit ip=%s", ip)
			w.WriteHeader(http.StatusTooManyRequests)
			if _, err := w.Write([]byte("429 Too Many Requests: Connection limit exceeded\n")); err != nil {
				log.Printf("failed to write 429 response: %v", err)
			}
			return
		}

		// Set reservation token in request context so websocket handler can commit it
		r = r.WithContext(context.WithValue(r.Context(), reservationTokenKey, reservationToken)) //nolint:contextcheck // We're properly using r.Context() to derive the new context

		// Log successful auth and proceed to upgrade
		log.Printf("WebSocket UPGRADE: ip=%s duration=%v", ip, time.Since(startTime))

		// Use websocket.Server to allow non-browser clients (no Origin header check)
		s := websocket.Server{
			Handler: wsHandler.Handle,
			Handshake: func(_ *websocket.Config, _ *http.Request) error {
				// Accept all connections - we do our own auth
				return nil
			},
		}
		s.ServeHTTP(w, r)
	})
	log.Println("Registered WebSocket handler at /ws")

	// No middleware - handle rate limiting inline for better control
	server := &http.Server{
		Addr:           *addr,
		Handler:        mux,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		IdleTimeout:    idleTimeout,
		MaxHeaderBytes: 1 << maxHeaderBytes, // 1MB
	}

	// Graceful shutdown
	done := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		log.Println("shutting down srv...")

		// Cancel the context to stop all components
		cancel()

		// Stop accepting new connections
		hub.Stop()

		// Stop the connection limiter cleanup routine
		connLimiter.Stop()

		// Give server time to complete active requests and flush responses
		// Quick shutdown if no active work, longer if processing requests
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("server shutdown error: %v", err)
		}

		// Wait for hub to finish
		hub.Wait()

		close(done)
	}()

	var err error

	if *letsencrypt {
		// Let's Encrypt automatic TLS
		if *leDomains == "" {
			log.Print("ERROR: Let's Encrypt requires -le-domains to be specified")
			return
		}

		domains := strings.Split(*leDomains, ",")
		for i := range domains {
			domains[i] = strings.TrimSpace(domains[i])
		}

		// Create cache directory if it doesn't exist
		if err := os.MkdirAll(*leCacheDir, 0o700); err != nil {
			log.Printf("failed to create Let's Encrypt cache directory: %v", err)
			return
		}

		certManager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domains...),
			Cache:      autocert.DirCache(*leCacheDir),
			Email:      *leEmail,
		}

		// Update server with autocert configuration
		server.Addr = ":443"
		server.TLSConfig = &tls.Config{
			GetCertificate: certManager.GetCertificate,
			MinVersion:     tls.VersionTLS13,
			CipherSuites:   nil, // Let Go choose secure defaults for TLS 1.3
		}

		// Start HTTP server for ACME challenges
		go func() {
			h := certManager.HTTPHandler(nil)
			acmeServer := &http.Server{
				Addr:         ":80",
				Handler:      h,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  120 * time.Second,
			}
			log.Println("starting HTTP server on :80 for Let's Encrypt ACME challenges")
			log.Println("NOTE: Port 80 must be accessible from the internet for certificate issuance/renewal")
			if err := acmeServer.ListenAndServe(); err != nil {
				log.Printf("HTTP ACME server error: %v", err)
				log.Print("WARNING: Let's Encrypt certificate issuance/renewal may fail without port 80")
			}
		}()

		log.Printf("starting HTTPS server on :443 with Let's Encrypt for domains: %v", domains)
		err = server.ListenAndServeTLS("", "")
	} else {
		// Plain HTTP
		log.Print("WARNING: TLS not enabled. Use -tls-cert/-tls-key or -letsencrypt for production")
		log.Printf("starting HTTP server on %s", *addr)
		err = server.ListenAndServe()
	}

	if err != http.ErrServerClosed {
		log.Printf("server error: %v", err)
		return
	}

	<-done
	log.Println("server stopped")
}
