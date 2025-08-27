// Package client provides a robust WebSocket client for connecting to webhook sprinkler servers.
// It handles automatic reconnection, ping/pong keep-alive, and comprehensive logging.
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
	// UI constants for logging.
	separatorLine = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	msgTypeField  = "type"
)

// Event represents a webhook event received from the server.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Raw       map[string]any
	Type      string `json:"type"`
	URL       string `json:"url"`
}

// Config holds the configuration for the client.
type Config struct {
	OnConnect      func()
	OnDisconnect   func(error)
	OnEvent        func(Event)
	ServerURL      string
	Token          string
	Organization   string
	EventTypes     []string
	PullRequests   []string // List of PR URLs to subscribe to
	MaxBackoff     time.Duration
	PingInterval   time.Duration
	MaxRetries     int
	UserEventsOnly bool
	Verbose        bool
	NoReconnect    bool
	Logger         *slog.Logger // Optional logger, defaults to text handler on stderr
}

// Client represents a WebSocket client with automatic reconnection.
type Client struct {
	ws         *websocket.Conn
	stopCh     chan struct{}
	stoppedCh  chan struct{}
	config     Config
	eventCount int
	retries    int
	mu         sync.RWMutex
	logger     *slog.Logger
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
	if config.Token == "" {
		return nil, errors.New("token is required")
	}

	// Set defaults
	if config.PingInterval == 0 {
		config.PingInterval = 30 * time.Second
	}
	if config.MaxBackoff == 0 {
		config.MaxBackoff = 30 * time.Second
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

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Client context cancelled, shutting down")
			return ctx.Err()
		case <-c.stopCh:
			c.logger.Info("Client stop requested")
			return nil
		default:
		}

		// Connection attempt logging
		if c.retries == 0 {
			c.logger.Info("========================================")
			c.logger.Info("CONNECTING to WebSocket server", "url", c.config.ServerURL)
			c.logger.Info("========================================")
		} else {
			c.logger.Info("========================================")
			c.logger.Info("RECONNECTING to WebSocket server", "url", c.config.ServerURL, "attempt", c.retries)
			c.logger.Info("========================================")
		}

		// Try to connect
		err := c.connect(ctx)
		// Handle connection result
		if err != nil {
			// Check if it's an authentication error - don't retry these
			var authErr *AuthenticationError
			if errors.As(err, &authErr) {
				c.logger.Error(separatorLine)
				c.logger.Error("AUTHENTICATION FAILED!", "error", err)
				c.logger.Error("This is likely due to:")
				c.logger.Error("- Invalid GitHub token")
				c.logger.Error("- Not being a member of the requested organization")
				c.logger.Error("- Insufficient permissions")
				c.logger.Error(separatorLine)
				return err
			}

			c.logger.Warn(separatorLine)
			c.logger.Warn("WebSocket CONNECTION LOST!", "error", err, "events_received", c.eventCount)
			c.logger.Warn(separatorLine)

			// Notify disconnect callback
			if c.config.OnDisconnect != nil {
				c.config.OnDisconnect(err)
			}

			// Check if reconnection is disabled
			if c.config.NoReconnect {
				return fmt.Errorf("connection failed and reconnection disabled: %w", err)
			}

			// Check retry limit
			c.retries++
			if c.config.MaxRetries > 0 && c.retries > c.config.MaxRetries {
				c.logger.Error("Exceeded maximum retry attempts. Giving up.", "max_retries", c.config.MaxRetries)
				return fmt.Errorf("exceeded maximum retry attempts (%d)", c.config.MaxRetries)
			}

			// Calculate backoff delay
			delay := time.Duration(c.retries) * time.Second
			if delay > c.config.MaxBackoff {
				delay = c.config.MaxBackoff
			}

			c.logger.Info("Will attempt to reconnect", "delay_seconds", delay.Seconds())
			c.logger.Info("Press Ctrl+C to exit")

			// Wait before reconnecting
			select {
			case <-time.After(delay):
				c.logger.Info("Reconnection delay elapsed, attempting to reconnect")
				continue
			case <-ctx.Done():
				return ctx.Err()
			case <-c.stopCh:
				return nil
			}
		}
	}
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
func (c *Client) connect(ctx context.Context) error {
	c.logger.Info("Establishing WebSocket connection")

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
	wsConfig.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", c.config.Token)}

	// Dial the server
	ws, err := websocket.DialConfig(wsConfig)
	if err != nil {
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

	// Set a read deadline for subscription confirmation to prevent indefinite hanging
	if err := ws.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read first response - should be either an error or subscription confirmation
	var firstResponse map[string]any
	if err := websocket.JSON.Receive(ws, &firstResponse); err != nil {
		return fmt.Errorf("failed to read subscription response (timeout after 10s): %w", err)
	}

	// Clear read deadline after successful read
	if err := ws.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("failed to clear read deadline: %w", err)
	}

	// Check response type
	responseType := ""
	if t, ok := firstResponse[msgTypeField].(string); ok {
		responseType = t
	}

	// Handle error response
	if responseType == "error" {
		errorCode := ""
		if code, ok := firstResponse["error"].(string); ok {
			errorCode = code
		}
		message := ""
		if msg, ok := firstResponse["message"].(string); ok {
			message = msg
		}
		c.logger.Error(separatorLine)
		c.logger.Error("SUBSCRIPTION REJECTED BY SERVER!", "error_code", errorCode, "message", message)
		c.logger.Error(separatorLine)

		// Return AuthenticationError for access denied errors to prevent retries
		if errorCode == "access_denied" {
			return &AuthenticationError{
				message: fmt.Sprintf("Access denied: %s", message),
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
	c.retries = 0

	// Start ping sender
	pingCtx, cancelPing := context.WithCancel(ctx)
	defer cancelPing()
	go c.sendPings(pingCtx, ws)

	// Don't process subscription_confirmed as an event
	// We've already handled it above

	// Read remaining events
	return c.readEvents(ctx, ws)
}

// sendPings sends periodic ping/pong messages to keep the connection alive.
func (c *Client) sendPings(ctx context.Context, ws *websocket.Conn) {
	ticker := time.NewTicker(c.config.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pong := map[string]string{msgTypeField: "pong"}
			c.logger.Debug("[KEEP-ALIVE] Sending periodic pong to maintain connection")
			if err := websocket.JSON.Send(ws, pong); err != nil {
				c.logger.Error("Failed to send keep-alive pong", "error", err)
				c.logger.Warn("Connection may be broken!")
				return
			}
			c.logger.Debug("[KEEP-ALIVE] ✓ Pong sent successfully")
		}
	}
}

// readEvents reads and processes events from the WebSocket.
func (c *Client) readEvents(ctx context.Context, ws *websocket.Conn) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Receive message
		var response map[string]any
		if err := websocket.JSON.Receive(ws, &response); err != nil {
			c.logger.Error(separatorLine)
			c.logger.Error("Lost connection while reading!", "error", err, "events_received", c.eventCount)
			c.logger.Error(separatorLine)
			return fmt.Errorf("read: %w", err)
		}

		// Check message type
		responseType := ""
		if t, ok := response[msgTypeField].(string); ok {
			responseType = t
		}

		// Handle ping messages
		if responseType == "ping" {
			c.logger.Debug("[PING-PONG] Received PING from server")
			pong := map[string]string{msgTypeField: "pong"}
			if err := websocket.JSON.Send(ws, pong); err != nil {
				c.logger.Error("[PING-PONG] Failed to send PONG response", "error", err)
				return fmt.Errorf("error sending pong response: %w", err)
			}
			c.logger.Debug("[PING-PONG] Sent PONG response to server")
			continue
		}

		// Handle pong acknowledgments
		if responseType == "pong" {
			c.logger.Debug("[PING-PONG] Received PONG acknowledgment from server")
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
				"raw", event.Raw)
		} else {
			if event.Type != "" && event.URL != "" {
				c.logger.Info("Event received",
					"timestamp", event.Timestamp.Format("15:04:05"),
					"event_number", eventNum,
					"type", event.Type,
					"url", event.URL)
			} else {
				c.logger.Info("Event received",
					"timestamp", event.Timestamp.Format("15:04:05"),
					"event_number", eventNum,
					"response", response)
			}
		}

		if c.config.OnEvent != nil {
			c.config.OnEvent(event)
		}
	}
}
