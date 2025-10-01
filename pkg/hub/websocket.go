package hub

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/websocket"

	"github.com/codeGROOVE-dev/sprinkler/pkg/github"
	"github.com/codeGROOVE-dev/sprinkler/pkg/logger"
	"github.com/codeGROOVE-dev/sprinkler/pkg/security"
)

// Constants for WebSocket timeouts and limits.
const (
	pingInterval        = 54 * time.Second
	readTimeout         = 60 * time.Second // Must be > pingInterval to avoid false timeouts
	writeTimeout        = 10 * time.Second
	minTokenLength      = 40   // Minimum GitHub token length
	maxTokenLength      = 255  // Maximum GitHub token length
	maxSubscriptionSize = 8192 // Maximum subscription message size (8KB)
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

// PreValidateAuth checks if the request has a valid GitHub token before WebSocket upgrade.
// This allows us to return proper HTTP status codes before the connection is upgraded.
func (h *WebSocketHandler) PreValidateAuth(r *http.Request) bool {
	if h.testMode {
		return true
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return false
	}

	githubToken := strings.TrimPrefix(authHeader, bearerPrefix)

	// Check length first (cheapest check)
	if len(githubToken) < minTokenLength || len(githubToken) > maxTokenLength {
		return false
	}

	// Then pattern (more expensive but still fast)
	if !githubTokenPattern.MatchString(githubToken) {
		return false
	}

	return true
}

// extractGitHubToken extracts and validates the GitHub token from the request.
func (h *WebSocketHandler) extractGitHubToken(ws *websocket.Conn, ip string) (string, bool) {
	if h.testMode {
		return "", true
	}

	authHeader := ws.Request().Header.Get("Authorization")
	if authHeader == "" {
		logger.Warn("WebSocket authentication failed: missing Authorization header", logger.Fields{
			"ip":         ip,
			"user_agent": ws.Request().UserAgent(),
			"path":       ws.Request().URL.Path,
		})
		return "", false
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		logger.Warn("WebSocket authentication failed: invalid Authorization header format", logger.Fields{
			"ip":            ip,
			"user_agent":    ws.Request().UserAgent(),
			"path":          ws.Request().URL.Path,
			"header_prefix": authHeader[:min(10, len(authHeader))], // Log first 10 chars
		})
		return "", false
	}
	githubToken := strings.TrimPrefix(authHeader, bearerPrefix)

	if len(githubToken) < minTokenLength || len(githubToken) > maxTokenLength || !githubTokenPattern.MatchString(githubToken) {
		// Log token details for debugging without revealing the full token
		tokenPrefix := ""
		if len(githubToken) >= tokenPrefixLength {
			tokenPrefix = githubToken[:tokenPrefixLength]
		}
		logger.Warn("WebSocket authentication failed: invalid GitHub token format", logger.Fields{
			"ip":           ip,
			"user_agent":   ws.Request().UserAgent(),
			"path":         ws.Request().URL.Path,
			"token_prefix": tokenPrefix,
			"token_length": len(githubToken),
		})
		return "", false
	}

	return githubToken, true
}

// readSubscription reads and validates the subscription from the WebSocket.
func (h *WebSocketHandler) readSubscription(ws *websocket.Conn, ip string) (Subscription, error) {
	var sub Subscription

	// Set max frame length to prevent DoS via large messages
	ws.MaxPayloadBytes = maxSubscriptionSize

	if h.testMode {
		// In test mode, accept a test subscription that includes username
		type testSubscription struct {
			Organization   string   `json:"organization"`
			Username       string   `json:"username,omitempty"`
			EventTypes     []string `json:"event_types,omitempty"`
			UserEventsOnly bool     `json:"user_events_only,omitempty"`
		}
		var testSub testSubscription
		if err := websocket.JSON.Receive(ws, &testSub); err != nil {
			log.Printf("failed to receive subscription from %s: %v", ip, err)
			return sub, err
		}
		sub.Organization = testSub.Organization
		sub.EventTypes = testSub.EventTypes
		sub.UserEventsOnly = testSub.UserEventsOnly
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
// Returns the list of organizations the user is a member of.
func (h *WebSocketHandler) validateAuth(ctx context.Context, ws *websocket.Conn, sub *Subscription, githubToken, ip string) ([]string, error) {
	if h.testMode {
		// In test mode, Username is already set from the test subscription
		// Return the single org they're subscribing to if specified
		if sub.Organization != "" {
			return []string{sub.Organization}, nil
		}
		return []string{}, nil
	}

	ghClient := github.NewClient(githubToken)

	// If organization is specified, validate membership
	//nolint:nestif // Complex org validation logic requires nested checks for different scenarios
	if sub.Organization != "" {
		// Handle wildcard organization - user wants to subscribe to all their orgs
		if sub.Organization == "*" {
			logger.Info("validating GitHub authentication for wildcard org subscription", logger.Fields{
				"ip": ip,
			})

			username, userOrgs, err := ghClient.UserAndOrgs(ctx)
			if err != nil {
				// Log token details for debugging
				tokenPrefix := ""
				if len(githubToken) >= tokenPrefixLength {
					tokenPrefix = githubToken[:tokenPrefixLength]
				}
				logger.Error("GitHub auth failed for wildcard org subscription", err, logger.Fields{
					"ip":           ip,
					"token_prefix": tokenPrefix,
					"token_length": len(githubToken),
				})

				// Send error response to client
				errorResp := map[string]string{
					"type":    "error",
					"error":   "authentication_failed",
					"message": "Authentication failed.",
				}

				// Set a write deadline to ensure we don't hang forever
				if err := ws.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
					logger.Error("failed to set write deadline", err, logger.Fields{"ip": ip})
					return nil, err
				}

				if sendErr := websocket.JSON.Send(ws, errorResp); sendErr != nil {
					logger.Error("failed to send error response to client", sendErr, logger.Fields{"ip": ip})
					return nil, sendErr
				}

				logger.Info("sent authentication error to client", logger.Fields{"ip": ip})
				return nil, errors.New("authentication failed")
			}

			logger.Info("GitHub authentication successful for wildcard org subscription", logger.Fields{
				"ip":        ip,
				"username":  username,
				"org_count": len(userOrgs),
			})

			// Set the authenticated username in subscription
			sub.Username = username
			return userOrgs, nil
		}

		// Regular org subscription - validate specific membership
		logger.Info("validating GitHub authentication and org membership", logger.Fields{
			"ip":  ip,
			"org": sub.Organization,
		})

		username, userOrgs, err := ghClient.ValidateOrgMembership(ctx, sub.Organization)
		if err != nil {
			// Log token details for debugging
			tokenPrefix := ""
			if len(githubToken) >= tokenPrefixLength {
				tokenPrefix = githubToken[:tokenPrefixLength]
			}
			logger.Error("GitHub auth/org membership validation failed", err, logger.Fields{
				"ip":           ip,
				"org":          sub.Organization,
				"token_prefix": tokenPrefix,
				"token_length": len(githubToken),
			})

			// Send error response to client
			errorResp := map[string]string{
				"type":    "error",
				"error":   "access_denied",
				"message": "Access denied.",
			}

			// Set a write deadline to ensure we don't hang forever
			if err := ws.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				logger.Error("failed to set write deadline", err, logger.Fields{"ip": ip})
				return nil, err
			}

			if sendErr := websocket.JSON.Send(ws, errorResp); sendErr != nil {
				logger.Error("failed to send error response to client", sendErr, logger.Fields{"ip": ip})
				return nil, sendErr
			}

			logger.Info("sent access denied error to client", logger.Fields{"ip": ip, "org": sub.Organization})
			return nil, errors.New("access denied")
		}

		logger.Info("GitHub authentication and org membership validated successfully", logger.Fields{
			"ip":        ip,
			"org":       sub.Organization,
			"username":  username,
			"org_count": len(userOrgs),
		})

		// Set the authenticated username in subscription
		sub.Username = username
		return userOrgs, nil
	}

	// No organization specified - just get user info and all their orgs
	// For GitHub Apps, this will auto-detect the installation org
	logger.Info("validating GitHub authentication (no org specified in subscription)", logger.Fields{
		"ip":               ip,
		"subscription_org": sub.Organization,
	})

	username, userOrgs, err := ghClient.UserAndOrgs(ctx)
	if err != nil {
		// Log token details for debugging
		tokenPrefix := ""
		if len(githubToken) >= tokenPrefixLength {
			tokenPrefix = githubToken[:tokenPrefixLength]
		}
		logger.Error("GitHub auth failed (no specific org)", err, logger.Fields{
			"ip":           ip,
			"token_prefix": tokenPrefix,
			"token_length": len(githubToken),
		})

		// Send error response to client
		errorResp := map[string]string{
			"type":    "error",
			"error":   "authentication_failed",
			"message": "Authentication failed. Please check your GitHub token.",
		}

		// Set a write deadline to ensure we don't hang forever
		if err := ws.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			logger.Error("failed to set write deadline", err, logger.Fields{"ip": ip})
			return nil, err
		}

		if sendErr := websocket.JSON.Send(ws, errorResp); sendErr != nil {
			logger.Error("failed to send error response to client", sendErr, logger.Fields{"ip": ip})
			return nil, sendErr
		}

		logger.Info("sent authentication error to client", logger.Fields{"ip": ip})
		return nil, errors.New("authentication failed")
	}

	logger.Info("GitHub authentication successful", logger.Fields{
		"ip":        ip,
		"username":  username,
		"org_count": len(userOrgs),
	})

	// Set the authenticated username in subscription
	sub.Username = username

	// For GitHub Apps with no org specified, auto-set to their installation org
	if strings.HasPrefix(username, "app[") && sub.Organization == "" && len(userOrgs) == 1 {
		sub.Organization = userOrgs[0]
		logger.Info("auto-setting GitHub App subscription to installation org", logger.Fields{
			"ip":  ip,
			"org": sub.Organization,
			"app": username,
		})
	}

	return userOrgs, nil
}

// Handle handles a WebSocket connection.
//
//nolint:funlen,gocyclo // This function orchestrates the complete WebSocket lifecycle and cannot be split without losing clarity
func (h *WebSocketHandler) Handle(ws *websocket.Conn) {
	// Log that we entered the handler
	log.Print("WebSocket Handle() started")

	// Use the request's context for proper lifecycle management
	ctx, cancel := context.WithCancel(ws.Request().Context())
	defer cancel()

	// Ensure WebSocket is properly closed
	defer func() {
		clientIP := security.ClientIP(ws.Request())
		log.Printf("WebSocket Handle() cleanup - closing connection for IP %s", clientIP)

		// Send a final shutdown message to allow graceful client disconnect
		shutdownMsg := map[string]string{"type": "server_closing", "code": "1001"}
		if err := ws.SetWriteDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			log.Printf("failed to set write deadline for shutdown message: %v", err)
		}
		if err := websocket.JSON.Send(ws, shutdownMsg); err != nil {
			// Expected during abrupt disconnection - don't log common cases
			if !strings.Contains(err.Error(), "use of closed network connection") &&
				!strings.Contains(err.Error(), "broken pipe") {
				log.Printf("failed to send shutdown message: %v", err)
			}
		}

		// Close the connection
		if err := ws.Close(); err != nil {
			// Check if it's already closed - not an error
			switch {
			case strings.Contains(err.Error(), "use of closed network connection"):
				log.Printf("WebSocket already closed for IP %s (expected during normal shutdown)", clientIP)
			case strings.Contains(err.Error(), "broken pipe"):
				log.Printf("WebSocket broken pipe for IP %s (client already disconnected)", clientIP)
			default:
				log.Printf("ERROR: failed to close websocket for IP %s: %v", clientIP, err)
			}
		}
	}()

	// Get client IP
	ip := security.ClientIP(ws.Request())
	log.Printf("WebSocket Handle() got IP: %s", ip)

	// Log incoming WebSocket request
	logger.Info("WebSocket connection attempt", logger.Fields{
		"ip":         ip,
		"user_agent": ws.Request().UserAgent(),
		"path":       ws.Request().URL.Path,
		"origin":     ws.Request().Header.Get("Origin"),
	})

	githubToken, ok := h.extractGitHubToken(ws, ip)
	if !ok {
		// Send 403 error response to client
		errorResp := map[string]string{
			"type":    "error",
			"error":   "authentication_failed",
			"message": "Invalid or missing GitHub token. Please provide a valid token in the Authorization header.",
		}

		// Try to send error response
		if err := ws.SetWriteDeadline(time.Now().Add(2 * time.Second)); err == nil {
			if sendErr := websocket.JSON.Send(ws, errorResp); sendErr != nil {
				logger.Error("failed to send 403 error response", sendErr, logger.Fields{"ip": ip})
			}
		}

		logger.Warn("WebSocket connection rejected: 403 Forbidden - authentication failed", logger.Fields{
			"ip":         ip,
			"user_agent": ws.Request().UserAgent(),
			"reason":     "invalid_token",
		})
		return
	}

	// Check connection limit
	if !h.connLimiter.Add(ip) {
		// Send 429 error response to client
		errorResp := map[string]string{
			"type":    "error",
			"error":   "connection_limit_exceeded",
			"message": "Too many connections from this IP address. Please try again later.",
		}

		// Try to send error response
		if err := ws.SetWriteDeadline(time.Now().Add(2 * time.Second)); err == nil {
			if sendErr := websocket.JSON.Send(ws, errorResp); sendErr != nil {
				logger.Error("failed to send 429 error response", sendErr, logger.Fields{"ip": ip})
			}
		}

		logger.Warn("WebSocket connection rejected: 429 Too Many Requests - connection limit exceeded", logger.Fields{
			"ip":         ip,
			"user_agent": ws.Request().UserAgent(),
		})
		return
	}
	defer h.connLimiter.Remove(ip)

	// Set read deadline for initial subscription (shorter timeout for handshake)
	if err := ws.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Printf("failed to set deadline for %s: %v", ip, err)
		return
	}

	// Read subscription
	sub, err := h.readSubscription(ws, ip)
	if err != nil {
		logger.Warn("WebSocket connection rejected: failed to read subscription", logger.Fields{
			"ip":         ip,
			"user_agent": ws.Request().UserAgent(),
			"error":      err.Error(),
		})
		return
	}

	// Reset deadline after successful read
	if err := ws.SetDeadline(time.Time{}); err != nil {
		log.Printf("failed to reset deadline for %s: %v", ip, err)
		return
	}

	// Organization is optional for PR subscriptions and UserEventsOnly mode

	// Validate subscription data
	if err := sub.Validate(); err != nil {
		// Send error response to client
		errorResp := map[string]string{
			"type":    "error",
			"error":   "invalid_subscription",
			"message": fmt.Sprintf("Invalid subscription: %v", err),
		}

		// Try to send error response
		if err := ws.SetWriteDeadline(time.Now().Add(2 * time.Second)); err == nil {
			if sendErr := websocket.JSON.Send(ws, errorResp); sendErr != nil {
				logger.Error("failed to send subscription error response", sendErr, logger.Fields{"ip": ip})
			}
		}

		logger.Warn("WebSocket connection rejected: invalid subscription", logger.Fields{
			"ip":         ip,
			"user_agent": ws.Request().UserAgent(),
			"error":      err.Error(),
			"org":        sub.Organization,
		})
		return
	}

	// Validate event types against server's allowed list
	if len(sub.EventTypes) > 0 && h.allowedEventsMap != nil {
		for _, requestedType := range sub.EventTypes {
			if !h.allowedEventsMap[requestedType] {
				// Send error response to client
				errorResp := map[string]string{
					"type":    "error",
					"error":   "event_type_not_allowed",
					"message": fmt.Sprintf("Event type '%s' is not allowed", requestedType),
				}

				// Try to send error response
				if err := ws.SetWriteDeadline(time.Now().Add(2 * time.Second)); err == nil {
					if sendErr := websocket.JSON.Send(ws, errorResp); sendErr != nil {
						logger.Error("failed to send event type error response", sendErr, logger.Fields{"ip": ip})
					}
				}

				logger.Warn("WebSocket connection rejected: event type not allowed", logger.Fields{
					"ip":         ip,
					"user_agent": ws.Request().UserAgent(),
					"event_type": requestedType,
					"org":        sub.Organization,
				})
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
	userOrgs, err := h.validateAuth(ctx, ws, &sub, githubToken, ip)
	if err != nil {
		// Error response already sent by validateAuth
		logger.Warn("WebSocket connection rejected: authentication/authorization failed", logger.Fields{
			"ip":         ip,
			"user_agent": ws.Request().UserAgent(),
			"org":        sub.Organization,
			"error":      err.Error(),
		})
		return
	}

	// Create client with unique ID using crypto-random only (no timestamp for security)
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	const idLength = 32 // 32 chars with 64 possible values = 192 bits of entropy
	id := make([]byte, idLength)
	for i := range id {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			// Critical security failure - cannot continue without secure randomness
			logger.Error("CRITICAL: failed to generate secure random client ID", err, logger.Fields{"ip": ip})
			// Send error to client before returning
			errorResp := map[string]string{
				"type":    "error",
				"error":   "internal_error",
				"message": "Failed to initialize secure session",
			}
			if sendErr := websocket.JSON.Send(ws, errorResp); sendErr != nil {
				logger.Error("failed to send error response", sendErr, logger.Fields{"ip": ip})
			}
			return
		}
		id[i] = charset[n.Int64()]
	}
	client := NewClient(
		string(id),
		sub,
		ws,
		h.hub,
		userOrgs,
	)

	logger.Info("WebSocket connection established", logger.Fields{
		"ip":               ip,
		"org":              sub.Organization,
		"user":             sub.Username,
		"event_types":      sub.EventTypes,
		"user_events_only": sub.UserEventsOnly,
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

	logger.Info("sent subscription confirmation to client", logger.Fields{
		"ip":        ip,
		"org":       sub.Organization,
		"client_id": client.ID,
		"time":      time.Now().Format(time.RFC3339),
	})

	// Register client
	h.hub.Register(client)
	defer func() {
		h.hub.Unregister(client.ID)
		logger.Info("WebSocket disconnected", logger.Fields{"ip": ip, "client_id": client.ID})
	}()

	// Start event sender in goroutine
	go client.Run(ctx, pingInterval, writeTimeout)

	// Handle incoming messages with responsive shutdown
	// Create a ticker for periodic context checks during blocking reads
	contextCheckTicker := time.NewTicker(1 * time.Second)
	defer contextCheckTicker.Stop()

	// Set initial read deadline - must be longer than pingInterval to avoid false timeouts
	if err := ws.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		log.Printf("failed to set read deadline for %s: %v", ip, err)
		return
	}

	// Message read loop with responsive shutdown
	for {
		select {
		case <-ctx.Done():
			log.Printf("client %s: context cancelled during read loop, shutting down", client.ID)
			return
		case <-contextCheckTicker.C:
			// Periodic check for context cancellation during blocking operations
			if ctx.Err() != nil {
				log.Printf("client %s: context cancelled during periodic check, shutting down", client.ID)
				return
			}
			continue
		default:
			// Non-blocking read attempt
		}

		var msg any
		err := websocket.JSON.Receive(ws, &msg)
		if err != nil {
			// Log why we're exiting the read loop
			switch {
			case err.Error() == "EOF":
				log.Printf("client %s closed connection (EOF received)", client.ID)
			case strings.Contains(err.Error(), "use of closed network connection"):
				log.Printf("client %s connection already closed", client.ID)
			case strings.Contains(err.Error(), "i/o timeout"):
				log.Printf("TIMEOUT: client %s read timeout at %s (no messages received for %v)",
					client.ID, time.Now().Format(time.RFC3339), readTimeout)
			default:
				log.Printf("client %s read error: %v", client.ID, err)
			}
			break
		}

		// Reset read deadline on any message
		if err := ws.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			log.Printf("failed to reset read deadline for client %s: %v", client.ID, err)
			break
		}

		// Check if it's a pong response or other expected message
		if msgMap, ok := msg.(map[string]any); ok {
			if msgType, ok := msgMap["type"].(string); ok {
				switch msgType {
				case "pong":
					// Pong received - connection is alive
					continue
				case "ping":
					// Client sent us a ping, send pong back
					pong := map[string]any{"type": "pong"}
					if seq, ok := msgMap["seq"]; ok {
						pong["seq"] = seq
					}
					if err := ws.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
						log.Printf("failed to set write deadline for pong to client %s: %v", client.ID, err)
						continue
					}
					if err := websocket.JSON.Send(ws, pong); err != nil {
						log.Printf("failed to send pong to client %s: %v", client.ID, err)
					}
					continue
				case "keepalive", "heartbeat":
					// Common keepalive messages - just acknowledge receipt
					continue
				default:
					// Fall through to log as unexpected
				}
			}
		}

		// Log only truly unexpected messages
		log.Printf("client %s sent unexpected message after subscription: %+v", client.ID, msg)
	}
}
