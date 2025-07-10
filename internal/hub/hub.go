package hub

import (
	"context"
	"log"
	"sync"
	"time"
)

// Event represents a GitHub webhook event that will be broadcast to clients.
// It contains the PR URL, timestamp, and event type from GitHub.
type Event struct {
	URL       string    `json:"url"`       // Pull request URL
	Timestamp time.Time `json:"timestamp"` // When the event occurred
	Type      string    `json:"type"`      // GitHub event type (e.g., "pull_request")
}

// Hub manages WebSocket clients and event broadcasting.
// It runs in its own goroutine and handles client registration,
// unregistration, and event distribution.
type Hub struct {
	mu         sync.RWMutex          // Protects clients map
	clients    map[string]*Client    // Connected clients by ID
	register   chan *Client          // Register requests from clients
	unregister chan string           // Unregister requests from clients
	broadcast  chan broadcastMsg     // Events to broadcast
	ctx        context.Context       // For graceful shutdown
	cancel     context.CancelFunc    // Cancel function for shutdown
}

// broadcastMsg contains an event and the payload for matching.
type broadcastMsg struct {
	event   Event
	payload map[string]interface{}
}

// NewHub creates a new client hub.
func NewHub() *Hub {
	ctx, cancel := context.WithCancel(context.Background())
	return &Hub{
		clients:    make(map[string]*Client),
		register:   make(chan *Client),
		unregister: make(chan string),
		broadcast:  make(chan broadcastMsg),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Run starts the hub's event loop.
func (h *Hub) Run() {
	
	for {
		select {
		case <-h.ctx.Done():
			log.Println("hub shutting down")
			return
			
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client.id] = client
			h.mu.Unlock()
			log.Printf("client registered: id=%s", client.id)

		case clientID := <-h.unregister:
			h.mu.Lock()
			if client, ok := h.clients[clientID]; ok {
				delete(h.clients, clientID)
				close(client.send)
				h.mu.Unlock()
				log.Printf("client unregistered: id=%s", clientID)
			} else {
				h.mu.Unlock()
			}

		case msg := <-h.broadcast:
			h.mu.RLock()
			matched := 0
			for _, client := range h.clients {
				if client.Matches(msg.event, msg.payload) {
					// Non-blocking send
					select {
					case client.send <- msg.event:
					default:
					}
					matched++
				}
			}
			log.Printf("broadcast event: type=%s matched=%d/%d clients",
				msg.event.Type, matched, len(h.clients))
			h.mu.RUnlock()
		}
	}
}

// Broadcast sends an event to all matching clients.
func (h *Hub) Broadcast(event Event, payload map[string]interface{}) {
	h.broadcast <- broadcastMsg{event: event, payload: payload}
}

// Cancel stops the hub.
func (h *Hub) Cancel() {
	h.cancel()
}

// Context returns the hub's context.
func (h *Hub) Context() context.Context {
	return h.ctx
}

// Register registers a new client.
func (h *Hub) Register(client *Client) {
	h.register <- client
}

// Unregister unregisters a client by ID.
func (h *Hub) Unregister(clientID string) {
	h.unregister <- clientID
}