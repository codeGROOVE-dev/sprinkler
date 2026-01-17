package srv

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"

	"github.com/codeGROOVE-dev/sprinkler/pkg/github"
	"github.com/codeGROOVE-dev/sprinkler/pkg/logger"
	"github.com/codeGROOVE-dev/sprinkler/pkg/security"
)

// Constants for WebSocket timeouts and limits.
const (
	pingInterval        = 54 * time.Second
	readTimeout         = 90 * time.Second // Must be > pingInterval + response time to avoid false timeouts
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
	hub                 *Hub
	connLimiter         *security.ConnectionLimiter
	allowedEventsMap    map[string]bool
	githubClientFactory func(token string) github.APIClient
	allowedEvents       []string
	testMode            bool
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
	return len(githubToken) >= minTokenLength &&
		len(githubToken) <= maxTokenLength &&
		githubTokenPattern.MatchString(githubToken)
}

// userAgentFromContext extracts client name and version from the parsed User-Agent in context.
// Returns "unknown" for both if not found (e.g., in tests).
func userAgentFromContext(ws *websocket.Conn) (clientName, clientVersion string) {
	ua, _ := ws.Request().Context().Value("user_agent").(*security.UserAgent) //nolint:errcheck,revive // Type assertion intentionally unchecked - nil is valid
	if ua != nil {
		return ua.Name, ua.Version
	}
	return "unknown", "unknown"
}

// extractGitHubToken extracts and validates the GitHub token from the request.
func (h *WebSocketHandler) extractGitHubToken(ctx context.Context, ws *websocket.Conn, ip string) (string, bool) {
	if h.testMode {
		return "", true
	}

	clientName, clientVersion := userAgentFromContext(ws)

	authHeader := ws.Request().Header.Get("Authorization")
	if authHeader == "" {
		logger.Warn(ctx, "WebSocket authentication failed: missing Authorization header", logger.Fields{
			"ip":             ip,
			"user_agent":     ws.Request().UserAgent(),
			"client_name":    clientName,
			"client_version": clientVersion,
			"path":           ws.Request().URL.Path,
		})
		return "", false
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		logger.Warn(ctx, "WebSocket authentication failed: invalid Authorization header format", logger.Fields{
			"ip":             ip,
			"user_agent":     ws.Request().UserAgent(),
			"client_name":    clientName,
			"client_version": clientVersion,
			"path":           ws.Request().URL.Path,
			"header_prefix":  authHeader[:min(10, len(authHeader))], // Log first 10 chars
		})
		return "", false
	}
	githubToken := strings.TrimPrefix(authHeader, bearerPrefix)

	if len(githubToken) < minTokenLength || len(githubToken) > maxTokenLength || !githubTokenPattern.MatchString(githubToken) {
		logger.Warn(ctx, "WebSocket authentication failed: invalid GitHub token format", logger.Fields{
			"ip":             ip,
			"user_agent":     ws.Request().UserAgent(),
			"client_name":    clientName,
			"client_version": clientVersion,
			"path":           ws.Request().URL.Path,
		})
		return "", false
	}

	return githubToken, true
}

// githubClient creates a GitHub API client using the factory if provided,
// otherwise uses the default client constructor.
func (h *WebSocketHandler) githubClient(token string) github.APIClient {
	if h.githubClientFactory != nil {
		return h.githubClientFactory(token)
	}
	return github.NewClient(token, nil)
}

// errorInfo holds error response details.
type errorInfo struct {
	code    string
	message string
	reason  string
}

// determineErrorInfo determines error code, message, and reason from error.
func determineErrorInfo(err error, username string, orgName string, userOrgs []string) errorInfo {
	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "invalid GitHub token"):
		return errorInfo{
			code:    "authentication_failed",
			message: "Invalid GitHub token.",
			reason:  "invalid_token",
		}
	case strings.Contains(errStr, "access forbidden"):
		return errorInfo{
			code:    "access_denied",
			message: "Access forbidden. Check token permissions.",
			reason:  "forbidden",
		}
	case strings.Contains(errStr, "rate limit"):
		return errorInfo{
			code:    "rate_limit_exceeded",
			message: "GitHub API rate limit exceeded. Try again later.",
			reason:  "rate_limit",
		}
	case strings.Contains(errStr, "not a member"):
		msg := fmt.Sprintf("You are not a member of organization '%s'.", orgName)
		if username != "" {
			if len(userOrgs) > 0 {
				msg = fmt.Sprintf("User '%s' is not a member of organization '%s'. Member of: %s",
					username, orgName, strings.Join(userOrgs, ", "))
			} else {
				msg = fmt.Sprintf("User '%s' is not a member of organization '%s'.", username, orgName)
			}
		}
		return errorInfo{
			code:    "access_denied",
			message: msg,
			reason:  "not_org_member",
		}
	default:
		return errorInfo{
			code:    "access_denied",
			message: "Access denied.",
			reason:  errStr,
		}
	}
}

// sendErrorResponse sends an error response to the WebSocket client.
func sendErrorResponse(ctx context.Context, ws *websocket.Conn, errInfo errorInfo, ip string) error {
	errorResp := map[string]string{
		"type":    "error",
		"error":   errInfo.code,
		"message": errInfo.message,
	}

	if err := ws.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		logger.Error(ctx, "failed to set write deadline", err, logger.Fields{"ip": ip})
		return err
	}

	if err := websocket.JSON.Send(ws, errorResp); err != nil {
		logger.Error(ctx, "failed to send error response to client", err, logger.Fields{"ip": ip})
		return err
	}

	// Allow time for client to receive error before connection closes.
	// Without this delay, TCP close can race with message delivery, causing clients to see EOF.
	time.Sleep(100 * time.Millisecond)

	return nil
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

// authErrorParams groups authentication error parameters.
//
//nolint:govet // Field order optimized for readability over minimal memory padding
type authErrorParams struct {
	userOrgs    []string
	githubToken string
	ip          string
	username    string
	orgName     string
	logContext  string
}

// handleAuthError handles authentication errors with consistent logging and response.
func (*WebSocketHandler) handleAuthError(ctx context.Context, ws *websocket.Conn, err error, params authErrorParams) error {
	errInfo := determineErrorInfo(err, params.username, params.orgName, params.userOrgs)

	logger.Error(ctx, params.logContext, err, logger.Fields{
		"ip":       params.ip,
		"org":      params.orgName,
		"username": params.username,
		"reason":   errInfo.reason,
	})

	if sendErr := sendErrorResponse(ctx, ws, errInfo, params.ip); sendErr != nil {
		return sendErr
	}

	logger.Info(ctx, "sent error to client", logger.Fields{
		"ip": params.ip, "error_code": errInfo.code, "error_reason": errInfo.reason,
	})

	return fmt.Errorf("%s: %w", errInfo.reason, err)
}

// validateWildcardOrg handles wildcard organization subscription.
func (h *WebSocketHandler) validateWildcardOrg(
	ctx context.Context, ws *websocket.Conn, sub *Subscription,
	ghClient github.APIClient, githubToken, ip string,
) ([]string, error) {
	logger.Info(ctx, "validating GitHub authentication for wildcard org subscription", logger.Fields{"ip": ip})

	username, userOrgs, err := ghClient.UserAndOrgs(ctx)
	if err != nil {
		return nil, h.handleAuthError(ctx, ws, err, authErrorParams{
			githubToken: githubToken,
			ip:          ip,
			logContext:  "GitHub auth failed for wildcard org subscription",
		})
	}

	logger.Info(ctx, "GitHub authentication successful for wildcard org subscription", logger.Fields{
		"ip": ip, "username": username, "org_count": len(userOrgs),
	})

	sub.Username = username
	return userOrgs, nil
}

// validateSpecificOrg handles specific organization membership validation.
func (h *WebSocketHandler) validateSpecificOrg(
	ctx context.Context, ws *websocket.Conn, sub *Subscription,
	ghClient github.APIClient, githubToken, ip string,
) ([]string, error) {
	logger.Info(ctx, "validating GitHub authentication and org membership", logger.Fields{
		"ip": ip, "org": sub.Organization,
	})

	username, userOrgs, err := ghClient.ValidateOrgMembership(ctx, sub.Organization)
	if err != nil {
		return nil, h.handleAuthError(ctx, ws, err, authErrorParams{
			githubToken: githubToken,
			ip:          ip,
			username:    username,
			orgName:     sub.Organization,
			userOrgs:    userOrgs,
			logContext:  "GitHub auth/org membership validation failed",
		})
	}

	logger.Info(ctx, "GitHub authentication and org membership validated successfully", logger.Fields{
		"ip": ip, "org": sub.Organization, "username": username, "org_count": len(userOrgs),
	})

	sub.Username = username
	return userOrgs, nil
}

// validateNoOrg handles authentication when no specific organization is requested.
func (h *WebSocketHandler) validateNoOrg(
	ctx context.Context, ws *websocket.Conn, sub *Subscription,
	ghClient github.APIClient, githubToken, ip string,
) ([]string, error) {
	logger.Info(ctx, "validating GitHub authentication (no org specified in subscription)", logger.Fields{
		"ip": ip, "subscription_org": sub.Organization,
	})

	username, userOrgs, err := ghClient.UserAndOrgs(ctx)
	if err != nil {
		return nil, h.handleAuthError(ctx, ws, err, authErrorParams{
			githubToken: githubToken,
			ip:          ip,
			logContext:  "GitHub auth failed (no specific org)",
		})
	}

	logger.Info(ctx, "GitHub authentication successful", logger.Fields{
		"ip": ip, "username": username, "org_count": len(userOrgs),
	})

	sub.Username = username

	// For GitHub Apps with no org specified, auto-set to their installation org
	if strings.HasPrefix(username, "app[") && sub.Organization == "" && len(userOrgs) == 1 {
		sub.Organization = userOrgs[0]
		logger.Info(ctx, "auto-setting GitHub App subscription to installation org", logger.Fields{
			"ip": ip, "org": sub.Organization, "app": username,
		})
	}

	return userOrgs, nil
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

	// Create GitHub client using factory if provided, otherwise use default
	var ghClient github.APIClient
	if h.githubClientFactory != nil {
		ghClient = h.githubClientFactory(githubToken)
	} else {
		ghClient = github.NewClient(githubToken, nil)
	}

	if sub.Organization != "" {
		if sub.Organization == "*" {
			return h.validateWildcardOrg(ctx, ws, sub, ghClient, githubToken, ip)
		}
		return h.validateSpecificOrg(ctx, ws, sub, ghClient, githubToken, ip)
	}

	return h.validateNoOrg(ctx, ws, sub, ghClient, githubToken, ip)
}

// wsCloser wraps a WebSocket connection with sync.Once to prevent double-close.
type wsCloser struct {
	ws        *websocket.Conn
	closeOnce sync.Once
	closed    bool
	mu        sync.Mutex
}

// Close closes the WebSocket connection exactly once.
func (wc *wsCloser) Close() error {
	var err error
	wc.closeOnce.Do(func() {
		err = wc.ws.Close()
		wc.mu.Lock()
		wc.closed = true
		wc.mu.Unlock()
	})
	return err
}

// IsClosed returns whether the connection has been closed.
func (wc *wsCloser) IsClosed() bool {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	return wc.closed
}

// closeWebSocket gracefully closes a WebSocket connection with cleanup.
// Uses sync.Once to ensure the connection is only closed once, preventing double-close panics.
//
// CRITICAL THREADING NOTE:
// This function MUST NOT send to client channels (send/control) because of a TOCTOU race:
//  1. Multiple cleanup paths can run concurrently:
//     - Handle() defer calls closeWebSocket()
//     - Handle() defer calls Hub.Unregister() which eventually calls client.Close()
//     - Client.Run() defer calls client.Close() on context cancellation
//     - Hub.cleanup() calls client.Close() during shutdown
//  2. client.Close() uses sync.Once to close all channels atomically (done, send, control)
//  3. Checking if client.done is closed doesn't guarantee client.control is still open
//  4. Race: check done (open) → another goroutine closes all channels → send to control → PANIC
//
// Instead, we rely on:
//   - WebSocket connection close will be detected by the client
//   - Context cancellation signals Client.Run() to exit gracefully
//   - Hub.Unregister() handles client cleanup asynchronously
func closeWebSocket(wc *wsCloser, client *Client, ip string) {
	log.Printf("WebSocket Handle() cleanup - closing connection for IP %s", ip)

	// DO NOT send shutdown message - creates race condition with client.Close()
	// The client will detect the WebSocket connection close, which is sufficient.
	if client != nil {
		log.Printf("Client %s cleanup - WebSocket close will signal disconnect", client.ID)
	}

	// Close the connection (sync.Once ensures this only happens once)
	if err := wc.Close(); err != nil {
		// Check if it's already closed - not an error
		switch {
		case strings.Contains(err.Error(), "use of closed network connection"):
			log.Printf("WebSocket already closed for IP %s (expected during normal shutdown)", ip)
		case strings.Contains(err.Error(), "broken pipe"):
			log.Printf("WebSocket broken pipe for IP %s (client already disconnected)", ip)
		default:
			log.Printf("ERROR: failed to close websocket for IP %s: %v", ip, err)
		}
	}
}

// Handle handles a WebSocket connection.
//
//nolint:funlen,gocyclo,gocognit,revive,maintidx // This function orchestrates the complete WebSocket lifecycle and cannot be split without losing clarity
func (h *WebSocketHandler) Handle(ws *websocket.Conn) {
	// Log that we entered the handler
	log.Print("WebSocket Handle() started")

	// Use the request's context for proper lifecycle management
	ctx, cancel := context.WithCancel(ws.Request().Context())
	defer cancel()

	// Get client IP early for logging
	ip := security.ClientIP(ws.Request())
	log.Printf("WebSocket Handle() got IP: %s", ip)

	// Wrap WebSocket with sync.Once closer to prevent double-close
	wc := &wsCloser{ws: ws}

	// Ensure WebSocket is properly closed (client will be set later if connection succeeds)
	var client *Client
	defer func() {
		closeWebSocket(wc, client, ip)
	}()

	// Get parsed User-Agent from context (set by main.go before upgrade)
	clientName, clientVersion := userAgentFromContext(ws)

	// Log incoming WebSocket request
	logger.Info(ctx, "WebSocket connection attempt", logger.Fields{
		"ip":             ip,
		"user_agent":     ws.Request().UserAgent(),
		"client_name":    clientName,
		"client_version": clientVersion,
		"path":           ws.Request().URL.Path,
		"origin":         ws.Request().Header.Get("Origin"),
	})

	// Get reservation token from context (set by main.go before upgrade)
	// Context key is a string type for package boundary crossing
	reservationToken, _ := ws.Request().Context().Value("reservation_token").(string) //nolint:errcheck // Type assertion intentionally unchecked - empty string is valid default
	if reservationToken == "" {
		// No reservation token - this should not happen in production
		// (main.go always sets it), but handle gracefully for tests
		log.Printf("WARNING: No reservation token in context for IP %s", ip)
	}

	// Cancel reservation on early return
	defer func() {
		if reservationToken != "" {
			h.connLimiter.CancelReservation(reservationToken)
		}
	}()

	githubToken, ok := h.extractGitHubToken(ctx, ws, ip)
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
				logger.Error(ctx, "failed to send 403 error response", sendErr, logger.Fields{"ip": ip})
			}
		}

		logger.Warn(ctx, "WebSocket connection rejected: 403 Forbidden - authentication failed", logger.Fields{
			"ip":             ip,
			"user_agent":     ws.Request().UserAgent(),
			"client_name":    clientName,
			"client_version": clientVersion,
			"reason":         "invalid_token",
		})
		return
	}

	// Commit the reservation to convert it to an active connection
	if reservationToken != "" {
		if !h.connLimiter.CommitReservation(reservationToken) {
			// Reservation expired or invalid - this shouldn't happen normally
			// Send 429 error response to client
			errorResp := map[string]string{
				"type":    "error",
				"error":   "connection_limit_exceeded",
				"message": "Connection reservation expired. Please try again.",
			}

			if err := ws.SetWriteDeadline(time.Now().Add(2 * time.Second)); err == nil {
				if sendErr := websocket.JSON.Send(ws, errorResp); sendErr != nil {
					logger.Error(ctx, "failed to send reservation expired error", sendErr, logger.Fields{"ip": ip})
				}
			}

			logger.Warn(ctx, "WebSocket connection rejected: reservation expired", logger.Fields{
				"ip":             ip,
				"user_agent":     ws.Request().UserAgent(),
				"client_name":    clientName,
				"client_version": clientVersion,
			})
			return
		}
		// Reservation committed - now set to empty so defer won't cancel it
		reservationToken = ""
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
		logger.Warn(ctx, "WebSocket connection rejected: failed to read subscription", logger.Fields{
			"ip":             ip,
			"user_agent":     ws.Request().UserAgent(),
			"client_name":    clientName,
			"client_version": clientVersion,
			"error":          err.Error(),
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
				logger.Error(ctx, "failed to send subscription error response", sendErr, logger.Fields{"ip": ip})
			}
		}

		logger.Warn(ctx, "WebSocket connection rejected: invalid subscription", logger.Fields{
			"ip":             ip,
			"user_agent":     ws.Request().UserAgent(),
			"client_name":    clientName,
			"client_version": clientVersion,
			"error":          err.Error(),
			"org":            sub.Organization,
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
						logger.Error(ctx, "failed to send event type error response", sendErr, logger.Fields{"ip": ip})
					}
				}

				logger.Warn(ctx, "WebSocket connection rejected: event type not allowed", logger.Fields{
					"ip":             ip,
					"user_agent":     ws.Request().UserAgent(),
					"client_name":    clientName,
					"client_version": clientVersion,
					"event_type":     requestedType,
					"org":            sub.Organization,
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
		logger.Warn(ctx, "WebSocket connection rejected: authentication/authorization failed", logger.Fields{
			"ip":             ip,
			"user_agent":     ws.Request().UserAgent(),
			"client_name":    clientName,
			"client_version": clientVersion,
			"org":            sub.Organization,
			"error":          err.Error(),
		})
		return
	}

	// Fetch user's GitHub Marketplace tier
	var tier github.Tier
	if cached, ok := h.hub.tierCache.Get(sub.Username); ok {
		tier = cached
		logger.Info(ctx, "using cached tier", logger.Fields{
			"username": sub.Username,
			"tier":     string(tier),
		})
	} else {
		// Create GitHub client for tier lookup
		ghClient := h.githubClient(githubToken)
		fetchedTier, tierErr := ghClient.UserTier(ctx, sub.Username)
		if tierErr != nil {
			logger.Warn(ctx, "failed to fetch marketplace tier, defaulting to free", logger.Fields{
				"username": sub.Username,
				"error":    tierErr.Error(),
			})
			tier = github.TierFree
		} else {
			tier = fetchedTier
			h.hub.tierCache.Set(sub.Username, tier)
			logger.Info(ctx, "fetched marketplace tier", logger.Fields{
				"username": sub.Username,
				"tier":     string(tier),
			})
		}
	}

	// Create client with unique ID using crypto-random only (no timestamp for security)
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	const idLength = 32 // 32 chars with 64 possible values = 192 bits of entropy
	id := make([]byte, idLength)
	for i := range id {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			// Critical security failure - cannot continue without secure randomness
			logger.Error(ctx, "CRITICAL: failed to generate secure random client ID", err, logger.Fields{"ip": ip})
			// Send error to client before returning
			errorResp := map[string]string{
				"type":    "error",
				"error":   "internal_error",
				"message": "Failed to initialize secure session",
			}
			if sendErr := websocket.JSON.Send(ws, errorResp); sendErr != nil {
				logger.Error(ctx, "failed to send error response", sendErr, logger.Fields{"ip": ip})
			}
			return
		}
		id[i] = charset[n.Int64()]
	}
	client = NewClient(ctx,
		string(id),
		sub,
		ws,
		h.hub,
		userOrgs,
		tier,
	)

	// Will be incremented when registered, but show current count
	currentClients := h.hub.ClientCount()

	log.Println("========================================")
	log.Printf("✅ NEW CLIENT CONNECTING: user=%s org=%s ip=%s client_id=%s (will be client #%d)",
		sub.Username, sub.Organization, ip, client.ID, currentClients+1)
	log.Println("========================================")
	logger.Info(ctx, "WebSocket connection established", logger.Fields{
		"ip":                 ip,
		"client_name":        clientName,
		"client_version":     clientVersion,
		"org":                sub.Organization,
		"user":               sub.Username,
		"client_id":          client.ID,
		"event_types":        sub.EventTypes,
		"user_events_only":   sub.UserEventsOnly,
		"will_be_client_num": currentClients + 1,
	})

	// Send success response to client immediately after successful subscription
	successResp := map[string]any{
		"type":                    "subscription_confirmed",
		"organization":            sub.Organization,
		"username":                sub.Username,
		"event_types":             sub.EventTypes,
		"tier":                    string(tier),
		"private_repos_enabled":   tier == github.TierPro || tier == github.TierFlock,
		"tier_enforcement_active": h.hub.enforceTiers,
	}

	// Set a write deadline for the success response
	if err := ws.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		logger.Error(ctx, "failed to set write deadline for success response", err, logger.Fields{
			"ip":             ip,
			"client_name":    clientName,
			"client_version": clientVersion,
		})
		return
	}

	if err := websocket.JSON.Send(ws, successResp); err != nil {
		logger.Error(ctx, "failed to send success response to client", err, logger.Fields{
			"ip":             ip,
			"client_name":    clientName,
			"client_version": clientVersion,
		})
		return
	}

	// Reset write deadline after successful send
	if err := ws.SetWriteDeadline(time.Time{}); err != nil {
		logger.Error(ctx, "failed to reset write deadline", err, logger.Fields{
			"ip":             ip,
			"client_name":    clientName,
			"client_version": clientVersion,
		})
		return
	}

	logger.Info(ctx, "sent subscription confirmation to client", logger.Fields{
		"ip":             ip,
		"client_name":    clientName,
		"client_version": clientVersion,
		"org":            sub.Organization,
		"client_id":      client.ID,
		"time":           time.Now().Format(time.RFC3339),
	})

	// Register client
	h.hub.Register(client)
	defer func() {
		h.hub.Unregister(client.ID)
		log.Println("========================================")
		log.Printf("❌ CLIENT DISCONNECTING: user=%s org=%s ip=%s client_id=%s",
			sub.Username, sub.Organization, ip, client.ID)
		log.Println("========================================")
		logger.Info(ctx, "WebSocket disconnected", logger.Fields{
			"ip":             ip,
			"client_name":    clientName,
			"client_version": clientVersion,
			"client_id":      client.ID,
			"user":           sub.Username,
			"org":            sub.Organization,
		})
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
					// No explicit tracking needed: the read loop's deadline reset
					// (which happens for ANY message including pong) keeps the connection alive
					continue
				case "ping":
					// Client sent us a ping, send pong back via control channel to avoid race
					pong := map[string]any{"type": "pong"}
					if seq, ok := msgMap["seq"]; ok {
						pong["seq"] = seq
					}
					// Non-blocking send to avoid deadlock if control channel is full
					select {
					case client.control <- pong:
						// Pong queued successfully
					default:
						log.Printf("WARNING: client %s control channel full, dropping pong", client.ID)
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
