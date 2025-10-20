// Package srv provides a WebSocket hub for managing client connections and broadcasting
// GitHub webhook events to subscribed clients based on their subscription criteria.
package srv

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/codeGROOVE-dev/sprinkler/pkg/logger"
)

// Event represents a GitHub webhook event that will be broadcast to clients.
// It contains the PR URL, timestamp, event type, and delivery ID from GitHub.
type Event struct {
	URL        string    `json:"url"`                   // Pull request URL
	Timestamp  time.Time `json:"timestamp"`             // When the event occurred
	Type       string    `json:"type"`                  // GitHub event type (e.g., "pull_request")
	DeliveryID string    `json:"delivery_id,omitempty"` // GitHub webhook delivery ID (unique per webhook)
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

const (
	// Channel buffer sizes.
	registerBufferSize   = 100
	unregisterBufferSize = 100
	broadcastBufferSize  = 1000
)

// NewHub creates a new client hub.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[string]*Client),
		register:   make(chan *Client, registerBufferSize),       // Buffer to prevent blocking
		unregister: make(chan string, unregisterBufferSize),      // Buffer to prevent blocking
		broadcast:  make(chan broadcastMsg, broadcastBufferSize), // Limited buffer to prevent memory exhaustion
		stop:       make(chan struct{}),
		stopped:    make(chan struct{}),
	}
}

// Run starts the hub's event loop.
// The context should be passed from main for proper lifecycle management.
func (h *Hub) Run(ctx context.Context) {
	defer close(h.stopped)
	defer h.cleanup()

	logger.Info("========================================", nil)
	logger.Info("HUB STARTED - Fresh hub with 0 clients", nil)
	logger.Info("========================================", nil)

	// Periodic client count logging (every minute)
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("hub shutting down", nil)
			return
		case <-h.stop:
			logger.Info("hub stop requested", nil)
			return

		case <-ticker.C:
			h.mu.RLock()
			count := len(h.clients)
			clientDetails := make([]string, 0, count)
			for _, client := range h.clients {
				clientDetails = append(clientDetails, fmt.Sprintf("%s@%s", client.subscription.Username, client.subscription.Organization))
			}
			h.mu.RUnlock()
			logger.Info("⏱️  PERIODIC CHECK", logger.Fields{
				"total_clients": count,
				"clients":       clientDetails,
			})

		case client := <-h.register:
			h.mu.Lock()
			h.clients[client.ID] = client
			totalClients := len(h.clients)
			h.mu.Unlock()
			logger.Info("CLIENT REGISTERED", logger.Fields{
				"client_id":     client.ID,
				"org":           client.subscription.Organization,
				"user":          client.subscription.Username,
				"total_clients": totalClients,
			})

		case clientID := <-h.unregister:
			h.mu.Lock()
			if client, ok := h.clients[clientID]; ok {
				delete(h.clients, clientID)
				totalClients := len(h.clients)
				client.Close()
				h.mu.Unlock()
				logger.Info("CLIENT UNREGISTERED", logger.Fields{
					"client_id":     clientID,
					"org":           client.subscription.Organization,
					"user":          client.subscription.Username,
					"total_clients": totalClients,
				})
			} else {
				h.mu.Unlock()
				logger.Warn("attempted to unregister unknown client", logger.Fields{
					"client_id": clientID,
				})
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
				if matches(client.subscription, msg.event, msg.payload, client.userOrgs) {
					// Non-blocking send
					select {
					case client.send <- msg.event:
						matched++
						logger.Info("delivered event to client", logger.Fields{
							"client_id":   client.ID,
							"user":        client.subscription.Username,
							"org":         client.subscription.Organization,
							"event_type":  msg.event.Type,
							"pr_url":      msg.event.URL,
							"delivery_id": msg.event.DeliveryID,
						})
					default:
						dropped++
						logger.Warn("dropped event for client: buffer full", logger.Fields{
							"client_id": client.ID,
						})
					}
				}
			}
			if totalClients == 0 {
				logger.Warn("⚠️⚠️⚠️  broadcast with ZERO clients connected ⚠️⚠️⚠️", nil)
				logger.Warn("⚠️  Event will be LOST", logger.Fields{
					"event_type":  msg.event.Type,
					"delivery_id": msg.event.DeliveryID,
					"pr_url":      msg.event.URL,
				})
				logger.Warn("⚠️  Possible reasons: fresh deployment, all clients disconnected, or network issue", nil)
			}
			logger.Info("broadcast event", logger.Fields{
				"event_type":    msg.event.Type,
				"delivery_id":   msg.event.DeliveryID,
				"matched":       matched,
				"total_clients": totalClients,
				"dropped":       dropped,
			})
		}
	}
}

// Broadcast sends an event to all matching clients.
func (h *Hub) Broadcast(event Event, payload map[string]any) {
	select {
	case h.broadcast <- broadcastMsg{event: event, payload: payload}:
	default:
		// Hub is at capacity or shutting down, drop the message
		logger.Warn("dropping broadcast: hub at capacity or shutting down", nil)
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

// ClientCount returns the current number of connected clients.
// Safe to call from any goroutine.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// cleanup closes all client connections during shutdown.
func (h *Hub) cleanup() {
	h.mu.Lock()
	defer h.mu.Unlock()

	logger.Info("Hub cleanup: closing client connections gracefully", logger.Fields{
		"client_count": len(h.clients),
	})

	for id, client := range h.clients {
		// Try to send shutdown message (non-blocking)
		select {
		case client.send <- Event{Type: "shutdown"}:
			logger.Info("sent shutdown notice to client", logger.Fields{"client_id": id})
		default:
			logger.Warn("could not send shutdown notice to client: channel full", logger.Fields{"client_id": id})
		}
	}

	// Give clients a moment to process shutdown messages and close gracefully
	// This allows time for proper WebSocket close frames to be sent
	if len(h.clients) > 0 {
		logger.Info("waiting for clients to receive shutdown messages", logger.Fields{
			"client_count": len(h.clients),
		})
		time.Sleep(200 * time.Millisecond)
	}

	// Now close all clients
	for _, client := range h.clients {
		client.Close()
	}
	h.clients = nil
	logger.Info("Hub cleanup complete", nil)
}
