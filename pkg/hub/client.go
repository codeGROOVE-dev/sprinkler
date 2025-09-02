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
// Context should be passed from the caller for proper lifecycle management.
func (c *Client) Run(ctx context.Context, pingInterval, writeTimeout time.Duration) {
	ticker := time.NewTicker(pingInterval)
	defer func() {
		ticker.Stop()
		// Don't close the websocket here - let the main handler do it
		// This prevents double-close errors
		c.Close()
	}()

	for {
		select {
		case event, ok := <-c.send:
			if !ok {
				log.Printf("client %s: send channel closed", c.ID)
				return
			}

			if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				log.Printf("error setting write deadline for client %s: %v", c.ID, err)
				return
			}
			if err := websocket.JSON.Send(c.conn, event); err != nil {
				log.Printf("error sending event to client %s: %v", c.ID, err)
				return
			}

		case <-ticker.C:
			// Send ping to keep connection alive
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				log.Printf("error setting ping deadline for client %s: %v", c.ID, err)
				return
			}
			ping := map[string]string{"type": "ping", "timestamp": time.Now().Format(time.RFC3339)}
			if err := websocket.JSON.Send(c.conn, ping); err != nil {
				log.Printf("error sending ping to client %s: %v", c.ID, err)
				return
			}
			// Ping sent successfully - debug logging disabled to avoid spam
			// log.Printf("DEBUG: Sent ping to client %s", c.ID)

		case <-c.done:
			log.Printf("client %s: done signal received", c.ID)
			return

		case <-ctx.Done():
			// Context cancellation usually means client disconnected
			var reason string
			switch ctx.Err() {
			case context.Canceled:
				reason = "client disconnected or connection lost"
			case context.DeadlineExceeded:
				reason = "connection timeout"
			case nil:
				reason = "context done without error"
			default:
				reason = fmt.Sprintf("context error: %v", ctx.Err())
			}
			log.Printf("client %s: context done (reason: %s)", c.ID, reason)
			return
		}
	}
}

// Close gracefully closes the client.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		close(c.done)
		close(c.send)
	})
}
