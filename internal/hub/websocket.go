package hub

import (
	"log"
	"time"

	"golang.org/x/net/websocket"

	"github.com/ready-to-review/github-event-socket/internal/security"
)

// Constants for WebSocket timeouts.
const (
	pingInterval = 54 * time.Second
	readDeadline = 60 * time.Second
	writeTimeout = 10 * time.Second
)

// WebSocketHandler handles WebSocket connections.
type WebSocketHandler struct {
	hub         *Hub
	connLimiter *security.ConnectionLimiter
}

// NewWebSocketHandler creates a new WebSocket handler.
func NewWebSocketHandler(h *Hub, connLimiter *security.ConnectionLimiter) *WebSocketHandler {
	return &WebSocketHandler{
		hub:         h,
		connLimiter: connLimiter,
	}
}

// Handle handles a WebSocket connection.
func (h *WebSocketHandler) Handle(ws *websocket.Conn) {
	// Get client IP
	ip := security.GetClientIP(ws.Request())

	// Check connection limit
	if !h.connLimiter.Add(ip) {
		ws.Close()
		return
	}
	defer h.connLimiter.Remove(ip)

	// Set read deadline for initial subscription
	ws.SetDeadline(time.Now().Add(5 * time.Second))

	// Read subscription
	var sub Subscription
	if err := websocket.JSON.Receive(ws, &sub); err != nil {
		ws.Close()
		return
	}

	// Reset deadline after successful read
	ws.SetDeadline(time.Time{})

	// Validate subscription
	if sub.IsEmpty() {
		log.Println("no subscription criteria provided")
		ws.Close()
		return
	}

	// Validate subscription data
	if err := sub.Validate(); err != nil {
		ws.Close()
		return
	}

	// Create client with unique ID
	client := NewClient(
		GenerateClientID(security.GenerateRandomString(8)),
		sub,
		ws,
		h.hub,
	)

	log.Printf("WebSocket connection from %s", ip)

	// Register client
	h.hub.Register(client)
	defer func() {
		h.hub.Unregister(client.ID())
		ws.Close()
		log.Printf("WebSocket disconnected from %s", ip)
	}()

	// Start event sender in goroutine
	go client.Run(pingInterval, writeTimeout)

	// Handle incoming messages (mainly for disconnection detection)

	ws.SetReadDeadline(time.Now().Add(readDeadline))
	for {
		var msg interface{}
		err := websocket.JSON.Receive(ws, &msg)
		if err != nil {
			break
		}
		// Reset read deadline on any message
		ws.SetReadDeadline(time.Now().Add(readDeadline))
		// We don't expect any messages from client after subscription
	}
}