package hub

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
type Client struct {
	conn            *websocket.Conn
	send            chan Event
	hub             *Hub
	done            chan struct{}
	userOrgs        map[string]bool
	ID              string
	subscription    Subscription
	lastPongTime    time.Time // Time of last pong
	mu              sync.RWMutex
	closeOnce       sync.Once
	pingSeq         int64 // Track ping sequence numbers
	lastPongSeq     int64 // Last pong sequence received
	missedPongCount int   // Count of consecutive missed pongs
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
// Context should be passed from the caller for proper lifecycle management.
func (c *Client) Run(ctx context.Context, pingInterval, writeTimeout time.Duration) {
	defer c.Close()

	// Start ping sender in separate goroutine to prevent event sends from blocking pings
	go c.sendPings(ctx, pingInterval, writeTimeout)

	// Handle event sending in main goroutine
	for {
		select {
		case <-ctx.Done():
			// Context cancellation usually means server shutdown or client disconnection
			var reason string
			switch ctx.Err() {
			case context.Canceled:
				reason = "server shutdown or client disconnected"
			case context.DeadlineExceeded:
				reason = "connection timeout"
			case nil:
				reason = "context done without error"
			default:
				reason = fmt.Sprintf("context error: %v", ctx.Err())
			}
			log.Printf("client %s: context done, shutting down (reason: %s)", c.ID, reason)
			return

		case event, ok := <-c.send:
			if !ok {
				log.Printf("client %s: send channel closed", c.ID)
				return
			}

			log.Printf("Sending event to client %s: type=%s", c.ID, event.Type)

			if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				log.Printf("error setting write deadline for client %s: %v", c.ID, err)
				return
			}
			if err := websocket.JSON.Send(c.conn, event); err != nil {
				log.Printf("error sending event to client %s: %v", c.ID, err)
				return
			}

			log.Printf("✓ Event sent to client %s", c.ID)

		case <-c.done:
			log.Printf("client %s: done signal received", c.ID)
			return
		}
	}
}

// sendPings sends periodic pings in a separate goroutine to prevent blocking by event sends.
func (c *Client) sendPings(ctx context.Context, pingInterval, writeTimeout time.Duration) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-ticker.C:
			// Check if we're missing pongs before sending next ping
			c.mu.RLock()
			currentSeq := c.pingSeq
			lastPongSeq := c.lastPongSeq
			c.mu.RUnlock()

			if currentSeq > 0 && lastPongSeq < currentSeq {
				c.mu.Lock()
				c.missedPongCount++
				missedCount := c.missedPongCount
				c.mu.Unlock()
				log.Printf("WARNING: client %s has not responded to ping #%d (missed %d consecutive pongs)",
					c.ID, currentSeq, missedCount)
			}

			// Send ping to keep connection alive
			c.mu.Lock()
			c.pingSeq++
			currentSeq = c.pingSeq
			c.mu.Unlock()

			if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				log.Printf("error setting ping deadline for client %s: %v", c.ID, err)
				return
			}
			ping := map[string]any{
				"type":      "ping",
				"timestamp": time.Now().Format(time.RFC3339),
				"seq":       currentSeq,
			}
			if err := websocket.JSON.Send(c.conn, ping); err != nil {
				log.Printf("error sending ping to client %s: %v", c.ID, err)
				return
			}
		}
	}
}

// RecordPong records receipt of a pong from the client.
func (c *Client) RecordPong(seq int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastPongSeq = seq
	c.lastPongTime = time.Now()
	c.missedPongCount = 0
}

// Close gracefully closes the client.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		close(c.done)
		close(c.send)
	})
}
