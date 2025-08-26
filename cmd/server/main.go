// Package main implements githooksock, a GitHub webhook listener that provides
// WebSocket subscriptions for pull request events to interested clients.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/websocket"

	"github.com/codeGROOVE-dev/sprinkler/pkg/hub"
	"github.com/codeGROOVE-dev/sprinkler/pkg/security"
	"github.com/codeGROOVE-dev/sprinkler/pkg/webhook"
)

const (
	readTimeout    = 10 * time.Second
	writeTimeout   = 10 * time.Second
	idleTimeout    = 120 * time.Second
	maxHeaderBytes = 20 // Max header size multiplier (1 << 20 = 1MB)
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
	rateLimit     = flag.Int("rate-limit", 100, "Maximum requests per minute per IP")
	allowedEvents = flag.String("allowed-events", os.Getenv("ALLOWED_WEBHOOK_EVENTS"),
		"Comma-separated list of allowed webhook event types (use '*' for all)")
	allowedOrigins = flag.String("allowed-origins", os.Getenv("ALLOWED_ORIGINS"),
		"Comma-separated list of allowed CORS origins (leave empty to disable CORS)")
)

func main() {
	flag.Parse()

	// Validate webhook secret is configured (REQUIRED for security)
	if *webhookSecret == "" {
		log.Fatal("ERROR: Webhook secret is required for security. Set -webhook-secret or GITHUB_WEBHOOK_SECRET environment variable.")
	}

	// Validate allowed events is configured (REQUIRED)
	if *allowedEvents == "" {
		log.Fatal("ERROR: Allowed events must be specified. Set -allowed-events or " +
			"ALLOWED_WEBHOOK_EVENTS environment variable. Use '*' to allow all events.")
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

	// Parse allowed origins for CORS
	var corsOrigins []string
	if *allowedOrigins != "" {
		corsOrigins = strings.Split(*allowedOrigins, ",")
		for i := range corsOrigins {
			corsOrigins[i] = strings.TrimSpace(corsOrigins[i])
		}
		log.Printf("Allowing CORS origins: %v", corsOrigins)
	} else {
		log.Println("CORS disabled - no origins allowed")
	}

	// Create context for the application
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := hub.NewHub()
	go h.Run(ctx)

	// Create security components
	rateLimiter := security.NewRateLimiter(*rateLimit, time.Minute)
	connLimiter := security.NewConnectionLimiter(*maxConnsPerIP, *maxConnsTotal)

	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request to %s from %s", r.URL.Path, r.RemoteAddr)
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("webhook-sprinkler is running\n")); err != nil {
				log.Printf("failed to write response: %v", err)
			}
			return
		}
		http.NotFound(w, r)
	})
	log.Println("Registered health check handler at /")

	webhookHandler := webhook.NewHandler(h, *webhookSecret, allowedEventTypes)
	mux.Handle("/webhook", webhookHandler)
	log.Println("Registered webhook handler at /webhook")

	wsHandler := hub.NewWebSocketHandler(h, connLimiter, allowedEventTypes)
	mux.Handle("/ws", websocket.Handler(wsHandler.Handle))
	log.Println("Registered WebSocket handler at /ws")

	// Apply combined middleware with allowed origins
	handler := security.CombinedMiddleware(rateLimiter, corsOrigins)(mux)

	server := &http.Server{
		Addr:           *addr,
		Handler:        handler,
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

		log.Println("shutting down server...")

		// Cancel the context to stop all components
		cancel()

		// Stop accepting new connections
		h.Stop()

		// Stop the rate limiter cleanup routine
		rateLimiter.Stop()

		// Stop the connection limiter cleanup routine
		connLimiter.Stop()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("server shutdown error: %v", err)
		}

		// Wait for hub to finish
		h.Wait()

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
