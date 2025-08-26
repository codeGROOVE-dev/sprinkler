package hub

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/websocket"

	"github.com/codeGROOVE-dev/sprinkler/pkg/github"
	"github.com/codeGROOVE-dev/sprinkler/pkg/logger"
	"github.com/codeGROOVE-dev/sprinkler/pkg/security"
)

// Constants for WebSocket timeouts.
const (
	pingInterval   = 54 * time.Second
	readDeadline   = 60 * time.Second
	writeTimeout   = 10 * time.Second
	minTokenLength = 40  // Minimum GitHub token length
	maxTokenLength = 255 // Maximum GitHub token length
	charsetLength  = 8   // Length of random suffix for client ID
)

// GitHub token validation regex
// Matches common GitHub token patterns:
// - ghp_* (Personal access tokens)
// - gho_* (OAuth tokens)
// - ghs_* (GitHub server tokens)
// - github_pat_* (Fine-grained PATs).
var githubTokenPattern = regexp.MustCompile(
	`^(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|` +
		`github_pat_[a-zA-Z0-9_]{36,255}|[a-zA-Z0-9]{40})$`,
)

// WebSocketHandler handles WebSocket connections.
type WebSocketHandler struct {
	hub              *Hub
	connLimiter      *security.ConnectionLimiter
	allowedEventsMap map[string]bool
	allowedEvents    []string
	testMode         bool
}

// NewWebSocketHandler creates a new WebSocket handler.
func NewWebSocketHandler(h *Hub, connLimiter *security.ConnectionLimiter, allowedEvents []string) *WebSocketHandler {
	// Build map for O(1) event type lookups
	var allowedMap map[string]bool
	if allowedEvents != nil {
		allowedMap = make(map[string]bool, len(allowedEvents))
		for _, event := range allowedEvents {
			allowedMap[event] = true
		}
	}

	return &WebSocketHandler{
		hub:              h,
		connLimiter:      connLimiter,
		allowedEvents:    allowedEvents,
		allowedEventsMap: allowedMap,
	}
}

// NewWebSocketHandlerForTest creates a WebSocket handler for testing that skips GitHub auth.
func NewWebSocketHandlerForTest(h *Hub, connLimiter *security.ConnectionLimiter, allowedEvents []string) *WebSocketHandler {
	handler := NewWebSocketHandler(h, connLimiter, allowedEvents)
	handler.testMode = true
	return handler
}

// extractGitHubToken extracts and validates the GitHub token from the request.
func (h *WebSocketHandler) extractGitHubToken(ws *websocket.Conn, ip string) (string, bool) {
	if h.testMode {
		return "", true
	}

	authHeader := ws.Request().Header.Get("Authorization")
	if authHeader == "" {
		logger.Warn("missing Authorization header", logger.Fields{"ip": ip})
		return "", false
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		logger.Warn("invalid Authorization header format", logger.Fields{"ip": ip})
		return "", false
	}
	githubToken := strings.TrimPrefix(authHeader, bearerPrefix)

	if len(githubToken) < minTokenLength || len(githubToken) > maxTokenLength || !githubTokenPattern.MatchString(githubToken) {
		logger.Warn("invalid GitHub token format", logger.Fields{"ip": ip})
		return "", false
	}

	return githubToken, true
}

// readSubscription reads and validates the subscription from the WebSocket.
func (h *WebSocketHandler) readSubscription(ws *websocket.Conn, ip string) (Subscription, error) {
	var sub Subscription

	if h.testMode {
		// In test mode, accept a test subscription that includes username
		type testSubscription struct {
			Organization string   `json:"organization"`
			Username     string   `json:"username,omitempty"`
			EventTypes   []string `json:"event_types,omitempty"`
			MyEventsOnly bool     `json:"my_events_only,omitempty"`
		}
		var testSub testSubscription
		if err := websocket.JSON.Receive(ws, &testSub); err != nil {
			log.Printf("failed to receive subscription from %s: %v", ip, err)
			return sub, err
		}
		sub.Organization = testSub.Organization
		sub.EventTypes = testSub.EventTypes
		sub.MyEventsOnly = testSub.MyEventsOnly
		sub.Username = testSub.Username // Preserve username for testing
		log.Printf("TEST MODE: Received subscription with Username=%q, Organization=%q", sub.Username, sub.Organization)
	} else {
		if err := websocket.JSON.Receive(ws, &sub); err != nil {
			log.Printf("failed to receive subscription from %s: %v", ip, err)
			return sub, err
		}
	}

	return sub, nil
}

// validateAuth validates the GitHub authentication and organization membership.
func (h *WebSocketHandler) validateAuth(ctx context.Context, ws *websocket.Conn, sub *Subscription, githubToken, ip string) error {
	if h.testMode {
		// In test mode, Username is already set from the test subscription
		return nil
	}

	logger.Info("validating GitHub authentication and org membership", logger.Fields{
		"ip":  ip,
		"org": sub.Organization,
	})

	// Validate GitHub token and org membership
	ghClient := github.NewClient(githubToken)
	username, err := ghClient.ValidateOrgMembership(ctx, sub.Organization)
	if err != nil {
		logger.Error("GitHub auth failed", err, logger.Fields{
			"ip":  ip,
			"org": sub.Organization,
		})

		// Send error response to client
		errorResp := map[string]string{
			"type":  "error",
			"error": "access_denied",
			"message": fmt.Sprintf("Access denied: You don't have access to organization '%s'. "+
				"Please ensure you are a member of this organization.", sub.Organization),
		}

		// Set a write deadline to ensure we don't hang forever
		if err := ws.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			logger.Error("failed to set write deadline", err, logger.Fields{"ip": ip})
			return err
		}

		if sendErr := websocket.JSON.Send(ws, errorResp); sendErr != nil {
			logger.Error("failed to send error response to client", sendErr, logger.Fields{"ip": ip})
			return sendErr
		}

		logger.Info("sent access denied error to client", logger.Fields{"ip": ip, "org": sub.Organization})
		return errors.New("access denied")
	}

	logger.Info("GitHub authentication and org membership validated successfully", logger.Fields{
		"ip":       ip,
		"org":      sub.Organization,
		"username": username,
	})

	// Set the authenticated username in subscription
	sub.Username = username
	return nil
}

// Handle handles a WebSocket connection.
func (h *WebSocketHandler) Handle(ws *websocket.Conn) {
	// Use the request's context for proper lifecycle management
	ctx, cancel := context.WithCancel(ws.Request().Context())
	defer cancel()

	// Ensure WebSocket is always closed
	defer func() {
		if err := ws.Close(); err != nil {
			log.Printf("failed to close websocket: %v", err)
		}
	}()

	// Get client IP
	ip := security.ClientIP(ws.Request())

	githubToken, ok := h.extractGitHubToken(ws, ip)
	if !ok {
		return
	}

	// Check connection limit
	if !h.connLimiter.Add(ip) {
		logger.Warn("connection limit exceeded", logger.Fields{"ip": ip})
		return
	}
	defer h.connLimiter.Remove(ip)

	// Set read deadline for initial subscription
	if err := ws.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Printf("failed to set deadline for %s: %v", ip, err)
		return
	}

	// Read subscription
	sub, err := h.readSubscription(ws, ip)
	if err != nil {
		return
	}

	// Reset deadline after successful read
	if err := ws.SetDeadline(time.Time{}); err != nil {
		log.Printf("failed to reset deadline for %s: %v", ip, err)
		return
	}

	// Validate subscription
	if sub.Organization == "" {
		log.Printf("empty subscription from %s - no organization provided", ip)
		return
	}

	// Validate subscription data
	if err := sub.Validate(); err != nil {
		log.Printf("invalid subscription from %s: %v", ip, err)
		return
	}

	// Validate event types against server's allowed list
	if len(sub.EventTypes) > 0 && h.allowedEventsMap != nil {
		for _, requestedType := range sub.EventTypes {
			if !h.allowedEventsMap[requestedType] {
				log.Printf("event type '%s' not allowed from %s", requestedType, ip)
				return
			}
		}
	}

	// If no event types specified, use all allowed events
	if len(sub.EventTypes) == 0 {
		if h.allowedEvents != nil {
			sub.EventTypes = h.allowedEvents
		}
		// If allowedEvents is nil, EventTypes remains empty, meaning all events
	}

	// Validate authentication and set username
	if err := h.validateAuth(ctx, ws, &sub, githubToken, ip); err != nil {
		return
	}

	// Create client with unique ID using crypto-random suffix
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	suffix := make([]byte, charsetLength)
	for i := range suffix {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			logger.Error("failed to generate random client ID", err, logger.Fields{"ip": ip})
			return
		}
		suffix[i] = charset[n.Int64()]
	}
	clientID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), string(suffix))
	client := NewClient(
		clientID,
		sub,
		ws,
		h.hub,
	)

	logger.Info("WebSocket connection established", logger.Fields{
		"ip":             ip,
		"org":            sub.Organization,
		"user":           sub.Username,
		"event_types":    sub.EventTypes,
		"my_events_only": sub.MyEventsOnly,
	})

	// Send success response to client immediately after successful subscription
	successResp := map[string]any{
		"type":         "subscription_confirmed",
		"organization": sub.Organization,
		"username":     sub.Username,
		"event_types":  sub.EventTypes,
	}

	// Set a write deadline for the success response
	if err := ws.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		logger.Error("failed to set write deadline for success response", err, logger.Fields{"ip": ip})
		return
	}

	if err := websocket.JSON.Send(ws, successResp); err != nil {
		logger.Error("failed to send success response to client", err, logger.Fields{"ip": ip})
		return
	}

	// Reset write deadline after successful send
	if err := ws.SetWriteDeadline(time.Time{}); err != nil {
		logger.Error("failed to reset write deadline", err, logger.Fields{"ip": ip})
		return
	}

	logger.Info("sent subscription confirmation to client", logger.Fields{"ip": ip, "org": sub.Organization})

	// Register client
	h.hub.Register(client)
	defer func() {
		h.hub.Unregister(client.ID)
		logger.Info("WebSocket disconnected", logger.Fields{"ip": ip, "client_id": client.ID})
	}()

	// Start event sender in goroutine
	go client.Run(ctx, pingInterval, writeTimeout)

	// Handle incoming messages (mainly for disconnection detection)

	if err := ws.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
		log.Printf("failed to set read deadline for %s: %v", ip, err)
		return
	}
	for {
		var msg any
		err := websocket.JSON.Receive(ws, &msg)
		if err != nil {
			break
		}
		// Reset read deadline on any message
		if err := ws.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
			log.Printf("failed to reset read deadline for %s: %v", ip, err)
			break
		}
		// We don't expect any messages from client after subscription
	}
}
