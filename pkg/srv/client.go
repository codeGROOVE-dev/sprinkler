package srv

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"

	"github.com/codeGROOVE-dev/sprinkler/pkg/github"
	"github.com/codeGROOVE-dev/sprinkler/pkg/logger"
)

// Client represents a connected WebSocket client with their subscription preferences.
//
// Connection management follows a simple pattern:
//   - ONE goroutine (Run) handles ALL writes to avoid concurrent write issues
//   - Server sends pings every pingInterval to detect dead connections
//   - Client responds with pongs; read loop resets deadline on any message
//   - Read loop (in websocket.go) detects disconnects and closes the connection
//
// Cleanup coordination (CRITICAL FOR THREAD SAFETY):
//
//	Multiple goroutines can trigger cleanup concurrently:
//	  1. Handle() defer in websocket.go calls Hub.Unregister() (async via channel)
//	  2. Handle() defer in websocket.go calls closeWebSocket() (closes WS connection)
//	  3. Client.Run() defer calls client.Close() when context is cancelled
//	  4. Hub.Run() processes unregister message and calls client.Close()
//	  5. Hub.cleanup() during shutdown calls client.Close() for all clients
//
//	Thread safety is ensured by:
//	  - Close() uses sync.Once to ensure channels are closed exactly once
//	  - closed atomic flag allows checking if client is closing (safe from any goroutine)
//	  - Hub checks closed flag before sending to avoid race with channel close
//	  - closeWebSocket() does NOT send to client channels (would race with Close)
//
//	Cleanup flow when a client disconnects:
//	  1. Handle() read loop exits (EOF, timeout, or error)
//	  2. defer cancel() signals Client.Run() via context
//	  3. defer Hub.Unregister(clientID) sends message to hub (returns immediately)
//	  4. defer closeWebSocket() closes the WebSocket connection only
//	  5. Client.Run() sees context cancellation, exits, calls defer client.Close()
//	  6. Hub.Run() processes unregister, calls client.Close() (idempotent via sync.Once)
type Client struct {
	conn         *websocket.Conn
	send         chan Event
	control      chan map[string]any // Control messages (pongs, shutdown notices)
	hub          *Hub
	done         chan struct{}
	userOrgs     map[string]bool
	ID           string
	subscription Subscription
	tier         github.Tier // GitHub Marketplace tier
	closeOnce    sync.Once
	closed       uint32 // Atomic flag: 1 if closed, 0 if open
}

// NewClient creates a new client.
func NewClient(ctx context.Context, id string, sub Subscription, conn *websocket.Conn, hub *Hub, userOrgs []string, tier github.Tier) *Client {
	// Limit the number of orgs to prevent memory exhaustion
	const maxOrgs = 1000
	orgsToProcess := userOrgs
	if len(userOrgs) > maxOrgs {
		orgsToProcess = userOrgs[:maxOrgs]
		logger.Warn(ctx, "user has too many organizations, limiting", logger.Fields{
			"user_org_count": len(userOrgs),
			"max_orgs":       maxOrgs,
		})
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
		send:         make(chan Event, 100),        // Increased buffer to reduce dropped messages
		control:      make(chan map[string]any, 5), // Buffer for control messages (pongs, shutdown)
		hub:          hub,
		done:         make(chan struct{}),
		userOrgs:     orgsMap,
		tier:         tier,
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
			logger.Debug(ctx, "client context cancelled, shutting down", logger.Fields{"client_id": c.ID})
			return

		case <-c.done:
			logger.Debug(ctx, "client done signal received", logger.Fields{"client_id": c.ID})
			return

		case <-pingTicker.C:
			// Send ping to keep connection alive and detect dead connections
			pingSeq++
			ping := map[string]any{
				"type": "ping",
				"seq":  pingSeq,
			}

			if err := c.write(ping, writeTimeout); err != nil {
				logger.Warn(ctx, "client ping failed", logger.Fields{
					"client_id": c.ID,
					"error":     err.Error(),
				})
				return
			}

		case ctrl, ok := <-c.control:
			if !ok {
				logger.Debug(ctx, "client control channel closed", logger.Fields{"client_id": c.ID})
				return
			}

			// Send control message (pong, shutdown notice, etc.)
			if err := c.write(ctrl, writeTimeout); err != nil {
				logger.Warn(ctx, "client control message send failed", logger.Fields{
					"client_id": c.ID,
					"error":     err.Error(),
				})
				return
			}

		case event, ok := <-c.send:
			if !ok {
				logger.Debug(ctx, "client send channel closed", logger.Fields{"client_id": c.ID})
				return
			}

			// Write event (hub already logged delivery, so we only log failures here)
			if err := c.write(event, writeTimeout); err != nil {
				logger.Warn(ctx, "client event send failed", logger.Fields{
					"client_id":  c.ID,
					"event_type": event.Type,
					"error":      err.Error(),
				})
				return
			}
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
		// Set closed flag BEFORE closing channels
		// This allows other goroutines to check if client is closing
		atomic.StoreUint32(&c.closed, 1)

		close(c.done)
		close(c.send)
		close(c.control)
	})
}

// IsClosed returns true if the client is closed or closing.
// Safe to call from any goroutine.
func (c *Client) IsClosed() bool {
	return atomic.LoadUint32(&c.closed) != 0
}

// CanAccessPrivateRepos returns true if the client's tier allows private repo access.
// Only Pro and Flock tiers have access to private repository events.
func (c *Client) CanAccessPrivateRepos() bool {
	return c.tier == github.TierPro || c.tier == github.TierFlock
}
