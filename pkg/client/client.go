package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/codeGROOVE-dev/retry"
	"golang.org/x/net/websocket"
)

// AuthenticationError represents an authentication or authorization failure
// that should not trigger reconnection attempts.
type AuthenticationError struct {
	message string
}

func (e *AuthenticationError) Error() string {
	return e.message
}

const (
	// DefaultServerAddress is the default webhook sprinkler server address.
	DefaultServerAddress = "webhook.github.codegroove.app"

	// UI constants for logging.
	separatorLine = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	msgTypeField  = "type"

	// Read timeout for WebSocket operations.
	// Set to 90s to be longer than server ping interval (54s) to avoid false timeouts.
	readTimeout = 90 * time.Second

	// Write channel buffer size.
	writeChannelBuffer = 10
)

// Event represents a webhook event received from the server.
type Event struct {
	Timestamp  time.Time `json:"timestamp"`
	Raw        map[string]any
	Type       string `json:"type"`
	URL        string `json:"url"`
	DeliveryID string `json:"delivery_id,omitempty"`
}

// Config holds the configuration for the client.
type Config struct {
	Logger         *slog.Logger
	OnDisconnect   func(error)
	OnEvent        func(Event)
	OnConnect      func()
	ServerURL      string
	Token          string
	TokenProvider  func() (string, error) // Optional: dynamically provide fresh tokens for reconnection
	Organization   string
	EventTypes     []string
	PullRequests   []string
	MaxBackoff     time.Duration
	PingInterval   time.Duration
	MaxRetries     int
	UserEventsOnly bool
	Verbose        bool
	NoReconnect    bool
}

// Client represents a WebSocket client with automatic reconnection.
// Connection management:
//   - Read loop (readEvents) receives all messages from server
//   - Write channel (writeCh) serializes all writes through one goroutine
//   - Server sends pings; client responds with pongs
//   - Client also sends pings; server responds with pongs
//   - Both sides use read timeouts to detect dead connections
//
//nolint:govet // Field alignment optimization would reduce readability
type Client struct {
	mu         sync.RWMutex
	config     Config
	logger     *slog.Logger
	ws         *websocket.Conn
	stopCh     chan struct{}
	stoppedCh  chan struct{}
	writeCh    chan any // Channel for serializing all writes
	eventCount int
	retries    int
}

// New creates a new robust WebSocket client.
func New(config Config) (*Client, error) {
	// Validate required fields
	if config.ServerURL == "" {
		return nil, errors.New("serverURL is required")
	}
	if config.Organization == "" && len(config.PullRequests) == 0 {
		return nil, errors.New("organization or pull requests required")
	}
	if config.Token == "" && config.TokenProvider == nil {
		return nil, errors.New("token or tokenProvider is required")
	}

	// Set defaults
	if config.PingInterval == 0 {
		config.PingInterval = 30 * time.Second
	}
	if config.MaxBackoff == 0 {
		config.MaxBackoff = 2 * time.Minute // Use exponential backoff up to 2 minutes
	}

	// Set default logger if not provided
	logger := config.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	return &Client{
		config:    config,
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
		logger:    logger,
	}, nil
}

// Start begins the connection process with automatic reconnection.
func (c *Client) Start(ctx context.Context) error {
	defer close(c.stoppedCh)

	// Create retry options
	retryOpts := []retry.Option{
		retry.Context(ctx),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.MaxDelay(c.config.MaxBackoff),
		retry.OnRetry(func(n uint, err error) {
			c.mu.Lock()
			//nolint:gosec // Retry count will not overflow in practice
			c.retries = int(n)
			c.mu.Unlock()

			c.logger.Warn(separatorLine)
			c.logger.Warn("WebSocket CONNECTION LOST!", "error", err, "events_received", c.eventCount, "attempt", n+1)
			c.logger.Warn(separatorLine)

			// Notify disconnect callback
			if c.config.OnDisconnect != nil {
				c.config.OnDisconnect(err)
			}
		}),
		retry.RetryIf(func(err error) bool {
			// Don't retry authentication errors
			var authErr *AuthenticationError
			if errors.As(err, &authErr) {
				c.logger.Error(separatorLine)
				c.logger.Error("AUTHENTICATION FAILED!", "error", err)
				c.logger.Error("This is likely due to:")
				c.logger.Error("- Invalid GitHub token")
				c.logger.Error("- Not being a member of the requested organization")
				c.logger.Error("- Insufficient permissions")
				c.logger.Error(separatorLine)
				return false
			}

			// Don't retry if reconnection is disabled
			if c.config.NoReconnect {
				return false
			}

			// Don't retry if stop was requested
			select {
			case <-c.stopCh:
				return false
			default:
				return true
			}
		}),
	}

	// Configure retry attempts
	if c.config.MaxRetries > 0 {
		//nolint:gosec // MaxRetries is a user-configured value, overflow not a concern
		retryOpts = append(retryOpts, retry.Attempts(uint(c.config.MaxRetries)))
	} else {
		retryOpts = append(retryOpts, retry.UntilSucceeded())
	}

	// Use retry library to handle reconnection with exponential backoff and jitter
	return retry.Do(func() error {
		// Check for early cancellation - don't retry on shutdown
		select {
		case <-ctx.Done():
			c.logger.Info("Client context cancelled, shutting down")
			return retry.Unrecoverable(ctx.Err())
		case <-c.stopCh:
			c.logger.Info("Client stop requested")
			return retry.Unrecoverable(errors.New("stop requested"))
		default:
		}

		// Connection attempt logging
		c.mu.RLock()
		n := c.retries
		c.mu.RUnlock()

		if n == 0 {
			c.logger.Info("========================================")
			c.logger.Info("CONNECTING to WebSocket server", "url", c.config.ServerURL)
			c.logger.Info("========================================")
		} else {
			c.logger.Info("========================================")
			c.logger.Info("RECONNECTING to WebSocket server", "url", c.config.ServerURL, "attempt", n)
			c.logger.Info("========================================")
		}

		// Try to connect - this will run indefinitely if successful
		return c.connect(ctx)
	}, retryOpts...)
}

// Stop gracefully stops the client.
func (c *Client) Stop() {
	close(c.stopCh)
	c.mu.Lock()
	if c.ws != nil {
		if closeErr := c.ws.Close(); closeErr != nil {
			c.logger.Error("Error closing websocket on shutdown", "error", closeErr)
		}
	}
	c.mu.Unlock()
	<-c.stoppedCh
}

// connect establishes a WebSocket connection and handles events.
//
//nolint:gocognit,funlen,maintidx // Connection lifecycle orchestration is inherently complex
func (c *Client) connect(ctx context.Context) error {
	c.logger.Info("Establishing WebSocket connection")

	// Get fresh token if TokenProvider is configured
	token := c.config.Token
	if c.config.TokenProvider != nil {
		t, err := c.config.TokenProvider()
		if err != nil {
			return fmt.Errorf("token provider: %w", err)
		}
		token = t
		c.logger.Debug("Using fresh token from TokenProvider")
	}

	// Create WebSocket config with appropriate origin
	origin := "http://localhost/"
	if strings.HasPrefix(c.config.ServerURL, "wss://") {
		origin = "https://localhost/"
	}
	wsConfig, err := websocket.NewConfig(c.config.ServerURL, origin)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Add Authorization header
	wsConfig.Header = make(map[string][]string)
	wsConfig.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", token)}

	// Dial the server
	ws, err := websocket.DialConfig(wsConfig)
	if err != nil {
		// Check for HTTP status codes in the error message
		errStr := err.Error()
		if strings.Contains(errStr, "bad status") {
			errLower := strings.ToLower(errStr)
			// Extract status code if present
			if strings.Contains(errStr, "403") || strings.Contains(errLower, "forbidden") {
				return &AuthenticationError{
					message: fmt.Sprintf(
						"Authentication failed (403 Forbidden): Check your GitHub token and organization membership. Original error: %v",
						err,
					),
				}
			}
			if strings.Contains(errStr, "401") || strings.Contains(errLower, "unauthorized") {
				return &AuthenticationError{
					message: fmt.Sprintf("Authentication failed (401 Unauthorized): Invalid or missing token. Original error: %v", err),
				}
			}
		}
		return fmt.Errorf("dial: %w", err)
	}
	c.logger.Info("✓ WebSocket connection ESTABLISHED successfully!")

	// Store connection
	c.mu.Lock()
	c.ws = ws
	c.mu.Unlock()

	defer func() {
		c.logger.Debug("Closing WebSocket connection")
		c.mu.Lock()
		c.ws = nil
		c.mu.Unlock()
		if err := ws.Close(); err != nil {
			c.logger.Error("Failed to close websocket cleanly", "error", err)
		} else {
			c.logger.Info("✓ WebSocket connection closed cleanly")
		}
	}()

	// Build subscription
	sub := map[string]any{
		"organization":     c.config.Organization,
		"user_events_only": c.config.UserEventsOnly,
	}

	// Add event types if specified
	if len(c.config.EventTypes) > 0 {
		// Check for wildcard
		if len(c.config.EventTypes) == 1 && c.config.EventTypes[0] == "*" {
			c.logger.Info("Subscribing to all event types")
			// Don't send event_types field - server interprets as all
		} else {
			sub["event_types"] = c.config.EventTypes
			c.logger.Info("Subscribing to event types", "types", c.config.EventTypes)
		}
	}

	// Add PR URLs if specified
	if len(c.config.PullRequests) > 0 {
		sub["pull_requests"] = c.config.PullRequests
		c.logger.Info("Subscribing to specific PRs", "count", len(c.config.PullRequests))
	}

	// Send subscription
	c.logger.Debug("Sending subscription request")
	if err := websocket.JSON.Send(ws, sub); err != nil {
		return fmt.Errorf("write subscription: %w", err)
	}
	c.logger.Debug("Waiting for subscription confirmation")

	// Set a short read deadline for subscription confirmation
	if err := ws.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read first response - should be either an error or subscription confirmation
	var firstResponse map[string]any
	if err := websocket.JSON.Receive(ws, &firstResponse); err != nil {
		return fmt.Errorf("failed to read subscription response (timeout after 2s): %w", err)
	}

	// Clear read deadline after successful read
	if err := ws.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("failed to clear read deadline: %w", err)
	}

	// Check response type
	responseType, ok := firstResponse[msgTypeField].(string)
	if !ok {
		responseType = ""
	}

	// Handle error response
	if responseType == "error" {
		errorCode, ok := firstResponse["error"].(string)
		if !ok {
			errorCode = ""
		}
		message, ok := firstResponse["message"].(string)
		if !ok {
			message = ""
		}
		c.logger.Error(separatorLine)
		c.logger.Error("SUBSCRIPTION REJECTED BY SERVER!", "error_code", errorCode, "message", message)
		c.logger.Error(separatorLine)

		// Return AuthenticationError for authentication/authorization errors to prevent retries
		if errorCode == "access_denied" || errorCode == "authentication_failed" {
			return &AuthenticationError{
				message: fmt.Sprintf("Authentication/authorization failed: %s", message),
			}
		}

		return fmt.Errorf("subscription rejected: %s - %s", errorCode, message)
	}

	// Handle subscription confirmation
	if responseType == "subscription_confirmed" {
		c.logger.Info("✓ Subscription confirmed by server!")
		if org, ok := firstResponse["organization"].(string); ok {
			if org == "*" {
				c.logger.Info("  Organization: * (all your organizations)")
			} else {
				c.logger.Info("  Subscription details", "organization", org)
			}
		}
		if username, ok := firstResponse["username"].(string); ok {
			c.logger.Info("  Subscription details", "username", username)
		}
		if eventTypes, ok := firstResponse["event_types"].([]any); ok && len(eventTypes) > 0 {
			types := make([]string, len(eventTypes))
			for i, t := range eventTypes {
				if s, ok := t.(string); ok {
					types[i] = s
				}
			}
			c.logger.Info("  Subscription details", "event_types", types)
		}
	} else {
		// For backward compatibility, treat any non-error response as success
		c.logger.Info("✓ Successfully subscribed", "response_type", responseType)
	}

	c.logger.Info("Listening for events...")

	// Notify connect callback
	if c.config.OnConnect != nil {
		c.config.OnConnect()
	}

	// Reset retry counter on successful connection
	c.mu.Lock()
	c.retries = 0
	c.mu.Unlock()

	// Create write channel for serializing all writes
	c.writeCh = make(chan any, writeChannelBuffer)

	// Start write pump - this is the ONLY goroutine that writes to the websocket
	writeCtx, cancelWrite := context.WithCancel(ctx)
	defer cancelWrite()
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- c.writePump(writeCtx, ws)
	}()

	// Start ping sender (sends to write channel, not directly to websocket)
	pingCtx, cancelPing := context.WithCancel(ctx)
	defer cancelPing()
	go c.sendPings(pingCtx)

	// Read events - when this returns, cancel everything
	readErr := c.readEvents(ctx, ws)

	// Stop write pump and ping sender
	cancelWrite()
	cancelPing()

	// Wait for write pump to finish
	writeErr := <-writeDone

	// Return the first error that occurred
	if readErr != nil {
		return readErr
	}
	return writeErr
}

// writePump is the ONLY goroutine that writes to the websocket.
// All writes must go through the writeCh channel to prevent concurrent writes.
func (c *Client) writePump(ctx context.Context, ws *websocket.Conn) error {
	const writeTimeout = 10 * time.Second

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case msg, ok := <-c.writeCh:
			if !ok {
				return errors.New("write channel closed")
			}

			// Set write deadline
			if err := ws.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				return fmt.Errorf("set write deadline: %w", err)
			}

			// Send message
			if err := websocket.JSON.Send(ws, msg); err != nil {
				return fmt.Errorf("write: %w", err)
			}
		}
	}
}

// sendPings sends periodic ping messages to keep the connection alive.
// Pings are sent to the write channel, not directly to the websocket.
func (c *Client) sendPings(ctx context.Context) {
	ticker := time.NewTicker(c.config.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ping := map[string]string{msgTypeField: "ping"}
			c.logger.Debug("[PING] Sending periodic ping to server")

			// Send to write channel (non-blocking)
			select {
			case c.writeCh <- ping:
				c.logger.Debug("[PING] ✓ Ping queued")
			case <-ctx.Done():
				return
			default:
				c.logger.Warn("[PING] Write channel full, skipping ping")
			}
		}
	}
}

// readEvents reads and processes events from the WebSocket with responsive shutdown.
func (c *Client) readEvents(ctx context.Context, ws *websocket.Conn) error {
	for {
		// Check for context cancellation first
		select {
		case <-ctx.Done():
			c.logger.Debug("readEvents: context cancelled, shutting down")
			return ctx.Err()
		default:
		}

		// Set read timeout for responsive shutdown
		if err := ws.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return fmt.Errorf("failed to set read timeout: %w", err)
		}

		// Receive message
		var response map[string]any
		err := websocket.JSON.Receive(ws, &response)
		if err != nil {
			// Check if it's a timeout error - may be normal during shutdown
			if strings.Contains(err.Error(), "i/o timeout") {
				// Check context again after timeout
				select {
				case <-ctx.Done():
					c.logger.Debug("readEvents: context cancelled during timeout, shutting down")
					return ctx.Err()
				default:
					// Continue reading if context is still active
					continue
				}
			}

			c.logger.Error(separatorLine)
			c.logger.Error("Lost connection while reading!", "error", err, "events_received", c.eventCount)
			c.logger.Error(separatorLine)
			return fmt.Errorf("read: %w", err)
		}

		// Check message type
		responseType, ok := response[msgTypeField].(string)
		if !ok {
			responseType = ""
		}

		// Handle ping messages from server
		if responseType == "ping" {
			c.logger.Debug("[PONG] Received PING from server")

			// Build pong response
			pong := map[string]any{msgTypeField: "pong"}
			if seq, ok := response["seq"]; ok {
				pong["seq"] = seq
			}

			// Send pong via write channel (non-blocking with timeout)
			select {
			case c.writeCh <- pong:
				c.logger.Debug("[PONG] Sent PONG response to server", "seq", pong["seq"])
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(1 * time.Second):
				c.logger.Error("[PONG] Failed to queue pong - write channel blocked")
				return errors.New("pong send blocked")
			}
			continue
		}

		// Handle pong acknowledgments from server
		if responseType == "pong" {
			c.logger.Debug("[PONG] Received PONG acknowledgment from server")
			continue
		}

		// Process the event inline
		event := Event{
			Type: responseType,
			Raw:  response,
		}

		if url, ok := response["url"].(string); ok {
			event.URL = url
		}

		if ts, ok := response["timestamp"].(string); ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				event.Timestamp = t
			}
		}

		if deliveryID, ok := response["delivery_id"].(string); ok {
			event.DeliveryID = deliveryID
		}

		c.mu.Lock()
		c.eventCount++
		eventNum := c.eventCount
		c.mu.Unlock()

		// Log event
		if c.config.Verbose {
			c.logger.Info("Event received",
				"event_number", eventNum,
				"timestamp", event.Timestamp.Format("15:04:05"),
				"type", event.Type,
				"url", event.URL,
				"delivery_id", event.DeliveryID,
				"raw", event.Raw)
		} else {
			if event.Type != "" && event.URL != "" {
				c.logger.Info("Event received",
					"timestamp", event.Timestamp.Format("15:04:05"),
					"event_number", eventNum,
					"type", event.Type,
					"url", event.URL,
					"delivery_id", event.DeliveryID)
			} else {
				c.logger.Info("Event received",
					"timestamp", event.Timestamp.Format("15:04:05"),
					"event_number", eventNum,
					"delivery_id", event.DeliveryID,
					"response", response)
			}
		}

		if c.config.OnEvent != nil {
			c.config.OnEvent(event)
		}
	}
}
