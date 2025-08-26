// Package hub provides a WebSocket hub for managing client connections and broadcasting
// GitHub webhook events to subscribed clients based on their subscription criteria.
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
	clients    map[string]*Client
	register   chan *Client
	unregister chan string
	broadcast  chan broadcastMsg
	stop       chan struct{}
	stopped    chan struct{}
	mu         sync.RWMutex
}

// broadcastMsg contains an event and the payload for matching.
type broadcastMsg struct {
	payload map[string]any
	event   Event
}

// NewHub creates a new client hub.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[string]*Client),
		register:   make(chan *Client),
		unregister: make(chan string),
		broadcast:  make(chan broadcastMsg),
		stop:       make(chan struct{}),
		stopped:    make(chan struct{}),
	}
}

// Run starts the hub's event loop.
// The context should be passed from main for proper lifecycle management.
func (h *Hub) Run(ctx context.Context) {
	defer close(h.stopped)
	defer h.cleanup()

	for {
		select {
		case <-ctx.Done():
			log.Println("hub shutting down")
			return
		case <-h.stop:
			log.Println("hub stop requested")
			return

		case client := <-h.register:
			h.mu.Lock()
			h.clients[client.ID] = client
			h.mu.Unlock()
			log.Printf("client registered: id=%s", client.ID)

		case clientID := <-h.unregister:
			h.mu.Lock()
			if client, ok := h.clients[clientID]; ok {
				delete(h.clients, clientID)
				client.Close()
				h.mu.Unlock()
				log.Printf("client unregistered: id=%s", clientID)
			} else {
				h.mu.Unlock()
			}

		case msg := <-h.broadcast:
			// Create snapshot of clients to minimize lock time
			h.mu.RLock()
			clientSnapshot := make([]*Client, 0, len(h.clients))
			for _, client := range h.clients {
				clientSnapshot = append(clientSnapshot, client)
			}
			totalClients := len(h.clients)
			h.mu.RUnlock()

			// Broadcast to clients without holding lock
			matched := 0
			dropped := 0
			for _, client := range clientSnapshot {
				if matches(client.subscription, msg.event, msg.payload) {
					// Non-blocking send
					select {
					case client.send <- msg.event:
						matched++
					default:
						dropped++
						log.Printf("dropped event for client %s: buffer full", client.ID)
					}
				}
			}
			log.Printf("broadcast event: type=%s matched=%d/%d clients, dropped=%d",
				msg.event.Type, matched, totalClients, dropped)
		}
	}
}

// Broadcast sends an event to all matching clients.
func (h *Hub) Broadcast(event Event, payload map[string]any) {
	select {
	case h.broadcast <- broadcastMsg{event: event, payload: payload}:
	default:
		// Hub is at capacity or shutting down, drop the message
		log.Print("dropping broadcast: hub at capacity or shutting down")
	}
}

// Stop signals the hub to stop.
func (h *Hub) Stop() {
	select {
	case <-h.stop:
		// Already stopped
	default:
		close(h.stop)
	}
}

// Wait blocks until the hub has stopped.
func (h *Hub) Wait() {
	<-h.stopped
}

// Register registers a new client.
func (h *Hub) Register(client *Client) {
	h.register <- client
}

// Unregister unregisters a client by ID.
func (h *Hub) Unregister(clientID string) {
	h.unregister <- clientID
}

// cleanup closes all client connections during shutdown.
func (h *Hub) cleanup() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, client := range h.clients {
		client.Close()
	}
	h.clients = nil
}
