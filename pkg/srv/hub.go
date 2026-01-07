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
	URL        string    `json:"url"`                   // Pull request URL (or repo URL for check events with race condition)
	Timestamp  time.Time `json:"timestamp"`             // When the event occurred
	Type       string    `json:"type"`                  // GitHub event type (e.g., "pull_request")
	DeliveryID string    `json:"delivery_id,omitempty"` // GitHub webhook delivery ID (unique per webhook)
	CommitSHA  string    `json:"commit_sha,omitempty"`  // Commit SHA for check events (used to look up PR when URL is repo-only)
}

// Hub manages WebSocket clients and event broadcasting.
// It runs in its own goroutine and handles client registration,
// unregistration, and event distribution.
//
// Thread safety design:
//   - Single-goroutine pattern: Only Run() modifies the clients map
//   - All external operations (Register, Unregister, Broadcast) send to buffered channels
//   - ClientCount() uses RLock for safe concurrent reads
//   - Client snapshot pattern in broadcast minimizes lock time
//
// Unregister coordination:
//   - Unregister(clientID) sends message to channel and returns immediately (async)
//   - Run() processes unregister messages in order
//   - Calls client.Close() which is idempotent (sync.Once)
//   - Multiple concurrent unregisters for same client are safe
//
// Broadcast safety:
//   - Creates client snapshot with RLock, then releases lock
//   - Non-blocking send to client.send channel prevents deadlocks
//   - If client disconnects during iteration, send fails gracefully (channel full or closed)
//   - Client.Close() is safe to call multiple times during this window
//
//nolint:govet // Field order optimized for readability over memory padding
type Hub struct {
	clients               map[string]*Client
	register              chan *Client
	unregister            chan string
	broadcast             chan broadcastMsg
	stop                  chan struct{}
	stopped               chan struct{}
	mu                    sync.RWMutex
	periodicCheckInterval time.Duration // For testing; 0 means use default (1 minute)
	commitCache           *CommitCache  // Maps commit SHA → PR info for check event association
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
		clients:     make(map[string]*Client),
		register:    make(chan *Client, registerBufferSize),       // Buffer to prevent blocking
		unregister:  make(chan string, unregisterBufferSize),      // Buffer to prevent blocking
		broadcast:   make(chan broadcastMsg, broadcastBufferSize), // Limited buffer to prevent memory exhaustion
		stop:        make(chan struct{}),
		stopped:     make(chan struct{}),
		commitCache: NewCommitCache(),
	}
}

// Run starts the hub's event loop.
// The context should be passed from main for proper lifecycle management.
func (h *Hub) Run(ctx context.Context) {
	defer close(h.stopped)
	defer h.cleanup(ctx)

	logger.Info(ctx, "========================================", nil)
	logger.Info(ctx, "HUB STARTED - Fresh hub with 0 clients", nil)
	logger.Info(ctx, "========================================", nil)

	// Periodic client count logging (every minute by default)
	checkInterval := h.periodicCheckInterval
	if checkInterval == 0 {
		checkInterval = 1 * time.Minute
	}
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info(ctx, "hub shutting down", nil)
			return
		case <-h.stop:
			logger.Info(ctx, "hub stop requested", nil)
			return

		case <-ticker.C:
			h.mu.RLock()
			count := len(h.clients)
			clientDetails := make([]string, 0, count)
			for _, client := range h.clients {
				clientDetails = append(clientDetails, fmt.Sprintf("%s@%s", client.subscription.Username, client.subscription.Organization))
			}
			h.mu.RUnlock()
			logger.Info(ctx, "⏱️  PERIODIC CHECK", logger.Fields{
				"total_clients": count,
				"clients":       clientDetails,
			})

		case client := <-h.register:
			h.mu.Lock()
			h.clients[client.ID] = client
			totalClients := len(h.clients)
			h.mu.Unlock()
			logger.Info(ctx, "CLIENT REGISTERED", logger.Fields{
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
				logger.Info(ctx, "CLIENT UNREGISTERED", logger.Fields{
					"client_id":     clientID,
					"org":           client.subscription.Organization,
					"user":          client.subscription.Username,
					"total_clients": totalClients,
				})
			} else {
				h.mu.Unlock()
				logger.Warn(ctx, "attempted to unregister unknown client", logger.Fields{
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
					// Try to send (safe against closed channels)
					if h.trySendEvent(client, msg.event) {
						matched++
						logger.Info(ctx, "delivered event to client", logger.Fields{
							"client_id":   client.ID,
							"user":        client.subscription.Username,
							"org":         client.subscription.Organization,
							"event_type":  msg.event.Type,
							"pr_url":      msg.event.URL,
							"delivery_id": msg.event.DeliveryID,
						})
					} else {
						dropped++
						logger.Warn(ctx, "dropped event for client: channel full or closed", logger.Fields{
							"client_id": client.ID,
						})
					}
				}
			}
			if totalClients == 0 {
				logger.Warn(ctx, "⚠️⚠️⚠️  broadcast with ZERO clients connected ⚠️⚠️⚠️", nil)
				logger.Warn(ctx, "⚠️  Event will be LOST", logger.Fields{
					"event_type":  msg.event.Type,
					"delivery_id": msg.event.DeliveryID,
					"pr_url":      msg.event.URL,
				})
				logger.Warn(ctx, "⚠️  Possible reasons: fresh deployment, all clients disconnected, or network issue", nil)
			}
			logger.Info(ctx, "broadcast event", logger.Fields{
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
func (h *Hub) Broadcast(ctx context.Context, event Event, payload map[string]any) {
	select {
	case h.broadcast <- broadcastMsg{event: event, payload: payload}:
	default:
		// Hub is at capacity or shutting down, drop the message
		logger.Warn(ctx, "dropping broadcast: hub at capacity or shutting down", nil)
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

// CommitCache returns the hub's commit→PR cache for populating from webhook events.
func (h *Hub) CommitCache() *CommitCache {
	return h.commitCache
}

// trySendEvent attempts to send an event to a client's send channel.
// Returns true if sent successfully, false if channel is full or closed.
//
// CRITICAL: This function checks the client's closed flag before sending.
// This prevents race conditions where Client.Close() is called while Hub is broadcasting.
//
// Race scenario this handles:
//  1. Hub takes client snapshot (client in map, channels open)
//  2. Client.Close() is called (sets closed=1, then closes send channel)
//  3. Hub checks client.IsClosed() before sending
//  4. If closed=1, we don't attempt to send (avoiding panic)
//
// Note: There's still a tiny window between IsClosed() check and send where
// Close() could be called, so we keep recover() as a safety net.
func (*Hub) trySendEvent(client *Client, event Event) (sent bool) {
	// Check if client is closed before attempting send
	// This prevents most races with client.Close()
	if client.IsClosed() {
		return false
	}

	defer func() {
		if r := recover(); r != nil {
			// Channel was closed between IsClosed() check and send
			// This is a very rare race but possible, so we catch it
			sent = false
		}
	}()

	// Non-blocking send with panic protection
	select {
	case client.send <- event:
		return true
	default:
		return false
	}
}

// cleanup closes all client connections during shutdown.
//
// CRITICAL THREADING NOTE:
// This function MUST NOT send to client channels (send/control) because of race conditions:
//   - Client.Close() can be called concurrently from multiple places (Handle defer, Run defer, etc.)
//   - Once Close() starts, it closes all channels atomically
//   - Trying to send to a closed channel panics, even with select/default
//   - select/default only protects against FULL channels, not CLOSED channels
//
// Instead, we rely on:
//   - WebSocket connection close will signal the client
//   - Client.Run() will detect context cancellation and exit gracefully
//   - client.Close() is idempotent (sync.Once) so safe to call multiple times
func (h *Hub) cleanup(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	logger.Info(ctx, "Hub cleanup: closing client connections", logger.Fields{
		"client_count": len(h.clients),
	})

	// Close all clients. DO NOT try to send shutdown messages - race with client.Close()
	// The WebSocket connection close and context cancellation are sufficient signals.
	for id, client := range h.clients {
		client.Close()
		logger.Info(ctx, "closed client during hub cleanup", logger.Fields{"client_id": id})
	}

	h.clients = nil
	logger.Info(ctx, "Hub cleanup complete", nil)
}
