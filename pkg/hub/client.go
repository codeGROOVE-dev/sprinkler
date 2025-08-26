package hub

import (
	"context"
	"log"
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
	ID           string
	subscription Subscription
	closeOnce    sync.Once
}

// NewClient creates a new client.
func NewClient(id string, sub Subscription, conn *websocket.Conn, hub *Hub) *Client {
	return &Client{
		ID:           id,
		subscription: sub,
		conn:         conn,
		send:         make(chan Event, 100), // Increased buffer to reduce dropped messages
		hub:          hub,
		done:         make(chan struct{}),
	}
}

// Run handles sending events to the client and periodic pings.
// Context should be passed from the caller for proper lifecycle management.
func (c *Client) Run(ctx context.Context, pingInterval, writeTimeout time.Duration) {
	ticker := time.NewTicker(pingInterval)
	defer func() {
		ticker.Stop()
		if err := c.conn.Close(); err != nil {
			log.Printf("failed to close websocket connection: %v", err)
		}
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
			// Send ping as empty JSON object
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				log.Printf("error setting ping deadline for client %s: %v", c.ID, err)
				return
			}
			ping := map[string]string{"type": "ping"}
			if err := websocket.JSON.Send(c.conn, ping); err != nil {
				log.Printf("error sending ping to client %s: %v", c.ID, err)
				return
			}

		case <-c.done:
			log.Printf("client %s: done signal received", c.ID)
			return

		case <-ctx.Done():
			log.Printf("client %s: context cancelled", c.ID)
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
