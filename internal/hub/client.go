package hub

import (
	"fmt"
	"time"

	"golang.org/x/net/websocket"
)

// Client represents a connected WebSocket client with their subscription preferences.
type Client struct {
	id           string          // Unique client identifier
	subscription Subscription    // What events this client wants
	conn         *websocket.Conn // WebSocket connection
	send         chan Event      // Buffered channel of events to send
	hub          *Hub            // Reference to hub for unregistering
}

// NewClient creates a new client.
func NewClient(id string, sub Subscription, conn *websocket.Conn, hub *Hub) *Client {
	return &Client{
		id:           id,
		subscription: sub,
		conn:         conn,
		send:         make(chan Event, 10),
		hub:          hub,
	}
}

// ID returns the client's ID.
func (c *Client) ID() string {
	return c.id
}

// Send returns the client's send channel.
func (c *Client) Send() chan Event {
	return c.send
}

// Conn returns the client's websocket connection.
func (c *Client) Conn() *websocket.Conn {
	return c.conn
}

// Run handles sending events to the client and periodic pings.
func (c *Client) Run(pingInterval, writeTimeout time.Duration) {
	ticker := time.NewTicker(pingInterval)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case event, ok := <-c.send:
			if !ok {
				return
			}

			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := websocket.JSON.Send(c.conn, event); err != nil {
				return
			}

		case <-ticker.C:
			// Send ping frame
			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := websocket.Message.Send(c.conn, ""); err != nil {
				return
			}

		case <-c.hub.ctx.Done():
			return
		}
	}
}

// Matches determines if an event matches the client's subscription.
func (c *Client) Matches(event Event, payload map[string]interface{}) bool {
	return matches(c.subscription, event, payload)
}

// GenerateClientID generates a unique client ID.
func GenerateClientID(randomString string) string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), randomString)
}