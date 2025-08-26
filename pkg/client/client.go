// Package client provides a robust WebSocket client for connecting to webhook sprinkler servers.
// It handles automatic reconnection, ping/pong keep-alive, and comprehensive logging.
package client

import (
	"context"
	"errors"
	"fmt"
	"log"
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

// IsAuthenticationError checks if an error is an authentication error.
func IsAuthenticationError(err error) bool {
	var authErr *AuthenticationError
	return errors.As(err, &authErr)
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
	OnConnect    func()
	OnDisconnect func(error)
	OnEvent      func(Event)
	ServerURL    string
	Token        string
	Organization string
	EventTypes   []string
	MaxBackoff   time.Duration
	PingInterval time.Duration
	MaxRetries   int
	MyEventsOnly bool
	Verbose      bool
	NoReconnect  bool
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
	connected  bool
}

// New creates a new robust WebSocket client.
func New(config Config) (*Client, error) {
	// Validate required fields
	if config.ServerURL == "" {
		return nil, errors.New("serverURL is required")
	}
	if config.Organization == "" {
		return nil, errors.New("organization is required")
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

	return &Client{
		config:    config,
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
	}, nil
}

// Start begins the connection process with automatic reconnection.
func (c *Client) Start(ctx context.Context) error {
	defer close(c.stoppedCh)

	for {
		select {
		case <-ctx.Done():
			log.Println("Client context cancelled, shutting down")
			return ctx.Err()
		case <-c.stopCh:
			log.Println("Client stop requested")
			return nil
		default:
		}

		// Connection attempt logging
		if c.retries == 0 {
			log.Print("========================================")
			log.Printf("CONNECTING to WebSocket server at %s", c.config.ServerURL)
			log.Print("========================================")
		} else {
			log.Print("========================================")
			log.Printf("RECONNECTING to WebSocket server at %s (attempt #%d)", c.config.ServerURL, c.retries)
			log.Print("========================================")
		}

		// Try to connect
		err := c.connect(ctx)
		// Handle connection result
		if err != nil {
			// Check if it's an authentication error - don't retry these
			if IsAuthenticationError(err) {
				log.Print(separatorLine)
				log.Print("AUTHENTICATION FAILED!")
				log.Printf("Error: %v", err)
				log.Print("This is likely due to:")
				log.Print("- Invalid GitHub token")
				log.Print("- Not being a member of the requested organization")
				log.Print("- Insufficient permissions")
				log.Print(separatorLine)
				return err
			}

			log.Print(separatorLine)
			log.Print("WARNING: WebSocket CONNECTION LOST!")
			log.Printf("Error: %v", err)
			log.Printf("Events received before disconnect: %d", c.eventCount)
			log.Print(separatorLine)

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
				log.Printf("ERROR: Exceeded maximum retry attempts (%d). Giving up.", c.config.MaxRetries)
				return fmt.Errorf("exceeded maximum retry attempts (%d)", c.config.MaxRetries)
			}

			// Calculate backoff delay
			delay := time.Duration(c.retries) * time.Second
			if delay > c.config.MaxBackoff {
				delay = c.config.MaxBackoff
			}

			log.Printf(">>> Will attempt to reconnect in %v seconds <<<", delay.Seconds())
			log.Print(">>> Press Ctrl+C to exit <<<")

			// Wait before reconnecting
			select {
			case <-time.After(delay):
				log.Print(">>> Reconnection delay elapsed, attempting to reconnect...")
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
			log.Printf("Error closing websocket on shutdown: %v", closeErr)
		}
	}
	c.mu.Unlock()
	<-c.stoppedCh
}

// IsConnected returns whether the client is currently connected.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// EventCount returns the number of events received.
func (c *Client) EventCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.eventCount
}

// connect establishes a WebSocket connection and handles events.
func (c *Client) connect(ctx context.Context) error {
	log.Print(">>> Establishing WebSocket connection...")

	// Parse origin from URL
	origin := "http://localhost/"
	if strings.HasPrefix(c.config.ServerURL, "wss://") {
		origin = "https://localhost/"
	}

	// Create WebSocket config
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
	log.Print("✓ WebSocket connection ESTABLISHED successfully!")

	// Store connection
	c.mu.Lock()
	c.ws = ws
	c.connected = true
	c.mu.Unlock()

	defer func() {
		log.Print(">>> Closing WebSocket connection...")
		c.mu.Lock()
		c.connected = false
		c.ws = nil
		c.mu.Unlock()
		if err := ws.Close(); err != nil {
			log.Printf("ERROR: Failed to close websocket cleanly: %v", err)
		} else {
			log.Print("✓ WebSocket connection closed cleanly")
		}
	}()

	// Build subscription
	sub := map[string]any{
		"organization":   c.config.Organization,
		"my_events_only": c.config.MyEventsOnly,
	}

	// Add event types if specified
	if len(c.config.EventTypes) > 0 {
		// Check for wildcard
		if len(c.config.EventTypes) == 1 && c.config.EventTypes[0] == "*" {
			log.Println("Subscribing to all event types")
			// Don't send event_types field - server interprets as all
		} else {
			sub["event_types"] = c.config.EventTypes
			log.Printf("Subscribing to event types: %v", c.config.EventTypes)
		}
	}

	// Send subscription
	log.Print(">>> Sending subscription request...")
	if err := websocket.JSON.Send(ws, sub); err != nil {
		return fmt.Errorf("write subscription: %w", err)
	}
	log.Print(">>> Waiting for subscription confirmation...")

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
		log.Print(separatorLine)
		log.Print("SUBSCRIPTION REJECTED BY SERVER!")
		log.Printf("Error: %s", errorCode)
		log.Printf("Message: %s", message)
		log.Print(separatorLine)

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
		log.Print("✓ Subscription confirmed by server!")
		if org, ok := firstResponse["organization"].(string); ok {
			log.Printf("  Organization: %s", org)
		}
		if username, ok := firstResponse["username"].(string); ok {
			log.Printf("  Username: %s", username)
		}
		if eventTypes, ok := firstResponse["event_types"].([]any); ok && len(eventTypes) > 0 {
			types := make([]string, len(eventTypes))
			for i, t := range eventTypes {
				if s, ok := t.(string); ok {
					types[i] = s
				}
			}
			log.Printf("  Event types: %v", types)
		}
	} else {
		// For backward compatibility, treat any non-error response as success
		log.Printf("✓ Successfully subscribed (server response type: %s)", responseType)
	}

	log.Print(">>> Listening for events...")

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
			log.Print("[KEEP-ALIVE] Sending periodic pong to maintain connection...")
			if err := websocket.JSON.Send(ws, pong); err != nil {
				log.Printf("ERROR: Failed to send keep-alive pong: %v", err)
				log.Print(">>> Connection may be broken!")
				return
			}
			log.Print("[KEEP-ALIVE] ✓ Pong sent successfully")
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
			log.Print(separatorLine)
			log.Print("ERROR: Lost connection while reading!")
			log.Printf("Read error: %v", err)
			log.Printf("Events received before disconnect: %d", c.eventCount)
			log.Print(separatorLine)
			return fmt.Errorf("read: %w", err)
		}

		// Check message type
		responseType := ""
		if t, ok := response[msgTypeField].(string); ok {
			responseType = t
		}

		// Handle ping messages
		if responseType == "ping" {
			log.Print("[PING-PONG] ← Received PING from server")
			pong := map[string]string{msgTypeField: "pong"}
			if err := websocket.JSON.Send(ws, pong); err != nil {
				log.Printf("[PING-PONG] ✗ Failed to send PONG response: %v", err)
				return fmt.Errorf("error sending pong response: %w", err)
			}
			log.Print("[PING-PONG] → Sent PONG response to server")
			continue
		}

		// Handle pong acknowledgments
		if responseType == "pong" {
			log.Print("[PING-PONG] ← Received PONG acknowledgment from server")
			continue
		}

		// Process the event
		c.processEvent(response)
	}
}

// processEvent processes a received event.
func (c *Client) processEvent(response map[string]any) {
	// Extract message type
	responseType := ""
	if t, ok := response[msgTypeField].(string); ok {
		responseType = t
	}

	// Parse event
	event := Event{
		Type: responseType,
		Raw:  response,
	}

	// Extract URL
	if url, ok := response["url"].(string); ok {
		event.URL = url
	}

	// Extract timestamp
	if ts, ok := response["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			event.Timestamp = t
		}
	}

	// Increment event counter
	c.mu.Lock()
	c.eventCount++
	eventNum := c.eventCount
	c.mu.Unlock()

	// Log event
	if c.config.Verbose {
		log.Printf("=== Event #%d at %s ===", eventNum, event.Timestamp.Format("15:04:05"))
		log.Printf("Type: %s", event.Type)
		log.Printf("URL: %s", event.URL)
		log.Printf("Raw: %+v", event.Raw)
	} else {
		if event.Type != "" && event.URL != "" {
			log.Printf("[%s] Event #%d: %s: %s",
				event.Timestamp.Format("15:04:05"), eventNum, event.Type, event.URL)
		} else {
			log.Printf("[%s] Event #%d received: %v",
				event.Timestamp.Format("15:04:05"), eventNum, response)
		}
	}

	// Notify callback
	if c.config.OnEvent != nil {
		c.config.OnEvent(event)
	}
}
