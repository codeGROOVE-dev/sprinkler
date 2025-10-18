package srv

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// Client represents a connected WebSocket client with their subscription preferences.
// Connection management follows a simple pattern:
//   - ONE goroutine (Run) handles ALL writes to avoid concurrent write issues
//   - Server sends pings every pingInterval to detect dead connections
//   - Client responds with pongs; read loop resets deadline on any message
//   - Read loop (in websocket.go) detects disconnects and closes the connection
type Client struct {
	conn         *websocket.Conn
	send         chan Event
	hub          *Hub
	done         chan struct{}
	userOrgs     map[string]bool
	ID           string
	subscription Subscription
	closeOnce    sync.Once
}

// NewClient creates a new client.
func NewClient(id string, sub Subscription, conn *websocket.Conn, hub *Hub, userOrgs []string) *Client {
	// Limit the number of orgs to prevent memory exhaustion
	const maxOrgs = 1000
	orgsToProcess := userOrgs
	if len(userOrgs) > maxOrgs {
		orgsToProcess = userOrgs[:maxOrgs]
		log.Printf("WARNING: User has %d organizations, limiting to %d", len(userOrgs), maxOrgs)
	}

	// Build a map for O(1) org membership lookups
	orgsMap := make(map[string]bool, len(orgsToProcess))
	for _, org := range orgsToProcess {
		// Store org names in lowercase for case-insensitive comparison
		orgsMap[strings.ToLower(org)] = true
	}

	return &Client{
		ID:           id,
		subscription: sub,
		conn:         conn,
		send:         make(chan Event, 100), // Increased buffer to reduce dropped messages
		hub:          hub,
		done:         make(chan struct{}),
		userOrgs:     orgsMap,
	}
}

// Run handles sending events to the client and periodic pings.
// CRITICAL: This is the ONLY goroutine that writes to the WebSocket connection.
// All writes go through this function to prevent concurrent write issues.
//
// Connection management:
//  1. Server sends ping every pingInterval (54s)
//  2. Client must respond with pong (read loop resets deadline on any message)
//  3. If client doesn't respond, read timeout (90s) will disconnect them
//  4. Any write error immediately closes the connection
func (c *Client) Run(ctx context.Context, pingInterval, writeTimeout time.Duration) {
	defer c.Close()

	// Ticker for periodic pings to detect dead connections
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

	// Sequence number for tracking ping/pong pairs (for debugging only)
	var pingSeq int64

	for {
		select {
		case <-ctx.Done():
			log.Printf("client %s: context cancelled, shutting down", c.ID)
			return

		case <-c.done:
			log.Printf("client %s: done signal received", c.ID)
			return

		case <-pingTicker.C:
			// Send ping to keep connection alive and detect dead connections
			pingSeq++
			ping := map[string]any{
				"type": "ping",
				"seq":  pingSeq,
			}

			if err := c.write(ping, writeTimeout); err != nil {
				log.Printf("client %s: ping failed: %v", c.ID, err)
				return
			}

		case event, ok := <-c.send:
			if !ok {
				log.Printf("client %s: send channel closed", c.ID)
				return
			}

			log.Printf("Sending event to client %s: type=%s", c.ID, event.Type)

			if err := c.write(event, writeTimeout); err != nil {
				log.Printf("client %s: event send failed: %v", c.ID, err)
				return
			}

			log.Printf("✓ Event sent to client %s", c.ID)
		}
	}
}

// write sends a message to the client with a write timeout.
// This is a helper to ensure consistent write deadline handling.
func (c *Client) write(msg any, timeout time.Duration) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if err := websocket.JSON.Send(c.conn, msg); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return nil
}

// Close gracefully closes the client.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		close(c.done)
		close(c.send)
	})
}
