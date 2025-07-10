// Package main implements githooksock, a GitHub webhook listener that provides
// WebSocket subscriptions for pull request events to interested clients.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/websocket"
)

const (
	maxPayloadSize = 1 << 20 // 1MB
	readTimeout    = 10 * time.Second
	writeTimeout   = 10 * time.Second
	idleTimeout    = 120 * time.Second
	pingInterval   = 54 * time.Second
	readDeadline   = 60 * time.Second
)

// Event represents a GitHub webhook event that will be broadcast to clients.
// It contains the PR URL, timestamp, and event type from GitHub.
type Event struct {
	URL       string    `json:"url"`       // Pull request URL
	Timestamp time.Time `json:"timestamp"` // When the event occurred
	Type      string    `json:"type"`      // GitHub event type (e.g., "pull_request")
}

// Subscription represents a client's subscription criteria.
// At least one field must be specified for a valid subscription.
type Subscription struct {
	Username   string `json:"username,omitempty"`   // GitHub username to watch
	PRURL      string `json:"pr_url,omitempty"`    // Specific PR URL to watch
	Repository string `json:"repository,omitempty"` // Repository URL to watch
}

// Client represents a connected WebSocket client with their subscription preferences.
type Client struct {
	id           string          // Unique client identifier
	subscription Subscription    // What events this client wants
	conn         *websocket.Conn // WebSocket connection
	send         chan Event      // Buffered channel of events to send
	hub          *Hub            // Reference to hub for unregistering
}

// Hub manages WebSocket clients and event broadcasting.
// It runs in its own goroutine and handles client registration,
// unregistration, and event distribution.
type Hub struct {
	mu         sync.RWMutex          // Protects clients map
	clients    map[string]*Client    // Connected clients by ID
	register   chan *Client          // Register requests from clients
	unregister chan string           // Unregister requests from clients
	broadcast  chan broadcastMsg     // Events to broadcast
	ctx        context.Context       // For graceful shutdown
	cancel     context.CancelFunc    // Cancel function for shutdown
}

// broadcastMsg contains an event and the payload for matching.
type broadcastMsg struct {
	event   Event
	payload map[string]interface{}
}


// NewHub creates a new client hub.
func NewHub() *Hub {
	ctx, cancel := context.WithCancel(context.Background())
	return &Hub{
		clients:    make(map[string]*Client),
		register:   make(chan *Client),
		unregister: make(chan string),
		broadcast:  make(chan broadcastMsg),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Run starts the hub's event loop.
func (h *Hub) Run() {
	
	for {
		select {
		case <-h.ctx.Done():
			log.Println("hub shutting down")
			return
			
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client.id] = client
			h.mu.Unlock()
			log.Printf("client registered: id=%s", client.id)

		case clientID := <-h.unregister:
			h.mu.Lock()
			if client, ok := h.clients[clientID]; ok {
				delete(h.clients, clientID)
				close(client.send)
				h.mu.Unlock()
				log.Printf("client unregistered: id=%s", clientID)
			} else {
				h.mu.Unlock()
			}

		case msg := <-h.broadcast:
			h.mu.RLock()
			matched := 0
			for _, client := range h.clients {
				if matches(client.subscription, msg.event, msg.payload) {
					// Non-blocking send
					select {
					case client.send <- msg.event:
					default:
					}
					matched++
				}
			}
			log.Printf("broadcast event: type=%s matched=%d/%d clients",
				msg.event.Type, matched, len(h.clients))
			h.mu.RUnlock()
		}
	}
}

// Broadcast sends an event to all matching clients.
func (h *Hub) Broadcast(event Event, payload map[string]interface{}) {
	h.broadcast <- broadcastMsg{event: event, payload: payload}
}

// matches determines if an event matches a client's subscription.
func matches(sub Subscription, event Event, payload map[string]interface{}) bool {
	// If no filters specified, match nothing (explicit subscription required)
	if sub.Username == "" && sub.PRURL == "" && sub.Repository == "" {
		return false
	}

	// Check PR URL match
	if sub.PRURL != "" && event.URL == sub.PRURL {
		return true
	}

	// Check repository match
	if sub.Repository != "" {
		if repo, ok := payload["repository"].(map[string]interface{}); ok {
			if htmlURL, ok := repo["html_url"].(string); ok && htmlURL == sub.Repository {
				return true
			}
		}
	}

	// Check username match (author, assignee, reviewer, mentioned)
	if sub.Username != "" {
		if matchesUser(sub.Username, payload) {
			return true
		}
	}

	return false
}



// matchesUser checks if a username matches any relevant field in the payload.
func matchesUser(username string, payload map[string]interface{}) bool {
	// Check PR author
	if pr, ok := payload["pull_request"].(map[string]interface{}); ok {
		if user, ok := pr["user"].(map[string]interface{}); ok {
			if login, ok := user["login"].(string); ok && login == username {
				return true
			}
		}

		// Check assignees
		if assignees, ok := pr["assignees"].([]interface{}); ok {
			for _, assignee := range assignees {
				if a, ok := assignee.(map[string]interface{}); ok {
					if login, ok := a["login"].(string); ok && login == username {
						return true
					}
				}
			}
		}

		// Check requested reviewers
		if reviewers, ok := pr["requested_reviewers"].([]interface{}); ok {
			for _, reviewer := range reviewers {
				if r, ok := reviewer.(map[string]interface{}); ok {
					if login, ok := r["login"].(string); ok && login == username {
						return true
					}
				}
			}
		}
	}

	// Check review author
	if review, ok := payload["review"].(map[string]interface{}); ok {
		if user, ok := review["user"].(map[string]interface{}); ok {
			if login, ok := user["login"].(string); ok && login == username {
				return true
			}
		}
	}

	// Check comment author
	if comment, ok := payload["comment"].(map[string]interface{}); ok {
		if user, ok := comment["user"].(map[string]interface{}); ok {
			if login, ok := user["login"].(string); ok && login == username {
				return true
			}
		}

		// Check mentions in comment body
		if body, ok := comment["body"].(string); ok {
			// Check for exact @username match (not partial)
			mentionPrefix := "@" + username
			if idx := strings.Index(body, mentionPrefix); idx >= 0 {
				// Check that it's not part of a longer username
				nextIdx := idx + len(mentionPrefix)
				if nextIdx >= len(body) {
					return true
				}
				nextChar := body[nextIdx]
				if !((nextChar >= 'a' && nextChar <= 'z') || (nextChar >= 'A' && nextChar <= 'Z') || (nextChar >= '0' && nextChar <= '9') || nextChar == '-') {
					return true
				}
			}
		}
	}

	// Check sender (action performer)
	if sender, ok := payload["sender"].(map[string]interface{}); ok {
		if login, ok := sender["login"].(string); ok && login == username {
			return true
		}
	}

	return false
}

// verifySignature validates the GitHub webhook signature.
func verifySignature(payload []byte, signature, secret string) bool {
	if secret == "" {
		return true // Skip verification if no secret configured
	}

	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expected))
}

// extractPRURL extracts the pull request URL from various event types.
func extractPRURL(eventType string, payload map[string]interface{}) string {
	switch eventType {
	case "pull_request", "pull_request_review", "pull_request_review_comment":
		if pr, ok := payload["pull_request"].(map[string]interface{}); ok {
			if htmlURL, ok := pr["html_url"].(string); ok {
				return htmlURL
			}
		}
	case "issue_comment":
		// issue_comment events can be on PRs too
		if issue, ok := payload["issue"].(map[string]interface{}); ok {
			if _, isPR := issue["pull_request"]; isPR {
				if htmlURL, ok := issue["html_url"].(string); ok {
					return htmlURL
				}
			}
		}
	case "check_run", "check_suite":
		// Extract PR URLs from check events if available
		if checkRun, ok := payload["check_run"].(map[string]interface{}); ok {
			if prs, ok := checkRun["pull_requests"].([]interface{}); ok && len(prs) > 0 {
				if pr, ok := prs[0].(map[string]interface{}); ok {
					if htmlURL, ok := pr["html_url"].(string); ok {
						return htmlURL
					}
				}
			}
		}
		if checkSuite, ok := payload["check_suite"].(map[string]interface{}); ok {
			if prs, ok := checkSuite["pull_requests"].([]interface{}); ok && len(prs) > 0 {
				if pr, ok := prs[0].(map[string]interface{}); ok {
					if htmlURL, ok := pr["html_url"].(string); ok {
						return htmlURL
					}
				}
			}
		}
	}
	return ""
}


// generateRandomString generates a cryptographically secure random string.
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

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

	// Errors
	errInvalidUsername = errors.New("invalid username")
	errInvalidURL      = errors.New("invalid URL")
)

func main() {
	flag.Parse()

	// Validate webhook secret is configured
	if *webhookSecret == "" {
		log.Println("WARNING: No webhook secret configured. Webhook signatures will not be verified!")
		log.Println("Set -webhook-secret or GITHUB_WEBHOOK_SECRET environment variable for security.")
	}

	hub := NewHub()
	go hub.Run()

	// Create security components
	rateLimiter := newRateLimiter(*rateLimit, time.Minute)
	connLimiter := newConnectionLimiter(*maxConnsPerIP, *maxConnsTotal)
	

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", webhookHandler(hub, *webhookSecret))
	mux.Handle("/ws", websocket.Handler(websocketHandler(hub, connLimiter)))

	// Apply middleware stack: recover -> security headers -> rate limit
	handler := rateLimitMiddleware(rateLimiter,
		securityMiddleware(
			recoverMiddleware(mux)))

	server := &http.Server{
		Addr:           *addr,
		Handler:        handler,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		IdleTimeout:    idleTimeout,
		MaxHeaderBytes: maxPayloadSize,
	}

	// Graceful shutdown
	done := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		log.Println("shutting down server...")
		
		// Stop accepting new connections
		hub.cancel()
		
		
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

// webhookHandler processes GitHub webhook events.
func webhookHandler(hub *Hub, secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		eventType := r.Header.Get("X-GitHub-Event")
		signature := r.Header.Get("X-Hub-Signature-256")
		deliveryID := r.Header.Get("X-GitHub-Delivery")
		

		// Check content length before reading
		if r.ContentLength > maxPayloadSize {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		
		// Read body
		body, err := io.ReadAll(io.LimitReader(r.Body, maxPayloadSize))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Verify signature
		if !verifySignature(body, signature, secret) {
					log.Printf("webhook signature verification failed for delivery: %s", deliveryID)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse payload
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}


		// Extract PR URL
		prURL := extractPRURL(eventType, payload)
		if prURL == "" {
			log.Printf("no PR URL found in %s event", eventType)
			w.WriteHeader(http.StatusOK)
			return
		}

		// Create and broadcast event
		event := Event{
			URL:       prURL,
			Timestamp: time.Now(),
			Type:      eventType,
		}

		hub.Broadcast(event, payload)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		log.Printf("processed webhook: event=%s delivery=%s", eventType, deliveryID)
	}
}

// websocketHandler handles WebSocket connections.
func websocketHandler(hub *Hub, connLimiter *connectionLimiter) func(*websocket.Conn) {
	return func(ws *websocket.Conn) {
		// Get client IP
		ip := getClientIP(ws.Request())

		// Check connection limit
		if !connLimiter.add(ip) {
			ws.Close()
			return
		}
		defer connLimiter.remove(ip)

		// Set read deadline for initial subscription
		ws.SetDeadline(time.Now().Add(5 * time.Second))

		// Read subscription
		var sub Subscription
		if err := websocket.JSON.Receive(ws, &sub); err != nil {
			ws.Close()
			return
		}

		// Reset deadline after successful read
		ws.SetDeadline(time.Time{})

		// Validate subscription
		if sub.Username == "" && sub.PRURL == "" && sub.Repository == "" {
			log.Println("no subscription criteria provided")
			ws.Close()
			return
		}

		// Validate subscription data
		if err := validateSubscription(&sub); err != nil {
			ws.Close()
			return
		}

		// Create client with unique ID
		client := &Client{
			id:           fmt.Sprintf("%d-%s", time.Now().UnixNano(), generateRandomString(8)),
			subscription: sub,
			conn:         ws,
			send:         make(chan Event, 10),
			hub:          hub,
		}

		log.Printf("WebSocket connection from %s", ip)

		// Register client
		hub.register <- client
		defer func() {
			hub.unregister <- client.id
			ws.Close()
			log.Printf("WebSocket disconnected from %s", ip)
		}()

		// Start event sender in goroutine
		go client.run()

		// Handle incoming messages (mainly for disconnection detection)

		ws.SetReadDeadline(time.Now().Add(readDeadline))
		for {
			var msg interface{}
			err := websocket.JSON.Receive(ws, &msg)
			if err != nil {
				break
			}
			// Reset read deadline on any message
			ws.SetReadDeadline(time.Now().Add(readDeadline))
			// We don't expect any messages from client after subscription
		}
	}
}

// run handles sending events to the client and periodic pings.
func (c *Client) run() {
	ticker := time.NewTicker(pingInterval)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case event, ok := <-c.send:
			if !ok {
				return
			}

			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := websocket.JSON.Send(c.conn, event); err != nil {
				return
			}

		case <-ticker.C:
			// Send ping frame
			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := websocket.Message.Send(c.conn, ""); err != nil {
				return
			}

		case <-c.hub.ctx.Done():
			return
		}
	}
}
