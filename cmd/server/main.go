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

	"github.com/ready-to-review/github-event-socket/internal/hub"
	"github.com/ready-to-review/github-event-socket/internal/security"
	"github.com/ready-to-review/github-event-socket/internal/webhook"
)

const (
	readTimeout  = 10 * time.Second
	writeTimeout = 10 * time.Second
	idleTimeout  = 120 * time.Second
)

var (
	webhookSecret  = flag.String("webhook-secret", os.Getenv("GITHUB_WEBHOOK_SECRET"), "GitHub webhook secret for signature verification")
	addr           = flag.String("addr", ":8080", "HTTP service address")
	letsencrypt    = flag.Bool("letsencrypt", false, "Use Let's Encrypt for automatic TLS certificates")
	leDomains      = flag.String("le-domains", "", "Comma-separated list of domains for Let's Encrypt certificates")
	leCacheDir     = flag.String("le-cache-dir", "./.letsencrypt", "Cache directory for Let's Encrypt certificates")
	leEmail        = flag.String("le-email", "", "Contact email for Let's Encrypt notifications")
	maxConnsPerIP  = flag.Int("max-conns-per-ip", 10, "Maximum WebSocket connections per IP")
	maxConnsTotal  = flag.Int("max-conns-total", 1000, "Maximum total WebSocket connections")
	rateLimit      = flag.Int("rate-limit", 100, "Maximum requests per minute per IP")
)

func main() {
	flag.Parse()

	// Validate webhook secret is configured
	if *webhookSecret == "" {
		log.Println("WARNING: No webhook secret configured. Webhook signatures will not be verified!")
		log.Println("Set -webhook-secret or GITHUB_WEBHOOK_SECRET environment variable for security.")
	}

	h := hub.NewHub()
	go h.Run()

	// Create security components
	rateLimiter := security.NewRateLimiter(*rateLimit, time.Minute)
	connLimiter := security.NewConnectionLimiter(*maxConnsPerIP, *maxConnsTotal)
	

	mux := http.NewServeMux()
	mux.Handle("/webhook", webhook.NewHandler(h, *webhookSecret))
	wsHandler := hub.NewWebSocketHandler(h, connLimiter)
	mux.Handle("/ws", websocket.Handler(wsHandler.Handle))

	// Apply combined middleware
	handler := security.CombinedMiddleware(rateLimiter)(mux)

	server := &http.Server{
		Addr:           *addr,
		Handler:        handler,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		IdleTimeout:    idleTimeout,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Graceful shutdown
	done := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		log.Println("shutting down server...")
		
		// Stop accepting new connections
		h.Cancel()
		
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("server shutdown error: %v", err)
		}
		close(done)
	}()

	var err error
	
	if *letsencrypt {
		// Let's Encrypt automatic TLS
		if *leDomains == "" {
			log.Fatal("Let's Encrypt requires -le-domains to be specified")
		}
		
		domains := strings.Split(*leDomains, ",")
		for i := range domains {
			domains[i] = strings.TrimSpace(domains[i])
		}
		
		// Create cache directory if it doesn't exist
		if err := os.MkdirAll(*leCacheDir, 0700); err != nil {
			log.Fatalf("failed to create Let's Encrypt cache directory: %v", err)
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
			MinVersion:     tls.VersionTLS12,
		}
		
		// Start HTTP server for ACME challenges  
		go func() {
			h := certManager.HTTPHandler(nil)
			log.Println("starting HTTP server on :80 for Let's Encrypt ACME challenges")
			log.Println("NOTE: Port 80 must be accessible from the internet for certificate issuance/renewal")
			if err := http.ListenAndServe(":80", h); err != nil {
				log.Printf("HTTP ACME server error: %v", err)
				log.Printf("WARNING: Let's Encrypt certificate issuance/renewal may fail without port 80")
			}
		}()
		
		log.Printf("starting HTTPS server on :443 with Let's Encrypt for domains: %v", domains)
		err = server.ListenAndServeTLS("", "")
		
	} else {
		// Plain HTTP
		log.Printf("WARNING: TLS not enabled. Use -tls-cert/-tls-key or -letsencrypt for production")
		log.Printf("starting HTTP server on %s", *addr)
		err = server.ListenAndServe()
	}

	if err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}

	<-done
	log.Println("server stopped")
}