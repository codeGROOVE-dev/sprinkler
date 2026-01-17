package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codeGROOVE-dev/retry"
	"github.com/codeGROOVE-dev/sprinkler/pkg/github"
	"golang.org/x/net/websocket"
)

// AuthenticationError represents an authentication or authorization failure
// that should not trigger reconnection attempts.
type AuthenticationError struct {
	message string
}

func (e *AuthenticationError) Error() string {
	return e.message
}

const (
	// DefaultServerAddress is the default webhook sprinkler server address.
	DefaultServerAddress = "webhook.github.codegroove.app"

	// Version is the client library version.
	Version = "v0.5.0"

	// UI constants for logging.
	separatorLine = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	msgTypeField  = "type"

	// Read timeout for WebSocket operations.
	// Set to 90s to be longer than server ping interval (54s) to avoid false timeouts.
	readTimeout = 90 * time.Second

	// Write channel buffer size.
	writeChannelBuffer = 10

	// Cache size limits to prevent memory exhaustion attacks.
	defaultMaxCacheSize = 512  // Soft limit - evict 25% when exceeded
	hardMaxCacheSize    = 1000 // Hard limit - aggressive eviction (50%)
)

// Event represents a webhook event received from the server.
type Event struct {
	Timestamp  time.Time `json:"timestamp"`
	Raw        map[string]any
	Type       string `json:"type"`
	URL        string `json:"url"` // PR URL (or repo URL for check events with race condition)
	DeliveryID string `json:"delivery_id,omitempty"`
	CommitSHA  string `json:"commit_sha,omitempty"` // Commit SHA for check events
}

// Config holds the configuration for the client.
type Config struct {
	Logger         *slog.Logger
	OnDisconnect   func(error)
	OnEvent        func(Event)
	OnConnect      func()
	ServerURL      string
	Token          string
	TokenProvider  func() (string, error) // Optional: dynamically provide fresh tokens for reconnection
	UserAgent      string                 // Required: User-Agent in format "client-name/version" (e.g., "myapp/v1.0.0")
	Organization   string
	EventTypes     []string
	PullRequests   []string
	MaxBackoff     time.Duration
	PingInterval   time.Duration
	MaxRetries     int
	UserEventsOnly bool
	Verbose        bool
	NoReconnect    bool
}

// Client represents a WebSocket client with automatic reconnection.
// Connection management:
//   - Read loop (readEvents) receives all messages from server
//   - Write channel (writeCh) serializes all writes through one goroutine
//   - Server sends pings; client responds with pongs
//   - Client also sends pings; server responds with pongs
//   - Both sides use read timeouts to detect dead connections
//
//nolint:govet // Field alignment optimization would reduce readability
type Client struct {
	mu         sync.RWMutex
	config     Config
	logger     *slog.Logger
	ws         *websocket.Conn
	stopCh     chan struct{}
	stoppedCh  chan struct{}
	stopOnce   sync.Once // Ensures Stop() is only executed once
	writeCh    chan any  // Channel for serializing all writes
	eventCount int
	retries    int

	// Cache for commit SHA to PR number lookups (for check event race condition)
	commitPRCache       map[string][]int     // key: "owner/repo:sha", value: PR numbers
	commitPRCacheExpiry map[string]time.Time // key: "owner/repo:sha", value: expiry time (only for empty results)
	commitCacheKeys     []string             // track insertion order for LRU eviction
	cacheMu             sync.RWMutex
	maxCacheSize        int
	emptyResultTTL      time.Duration // TTL for empty results (to handle GitHub indexing race)
}

// New creates a new robust WebSocket client.
func New(config Config) (*Client, error) {
	// Validate required fields
	if config.ServerURL == "" {
		return nil, errors.New("serverURL is required")
	}
	if config.UserAgent == "" {
		return nil, errors.New("userAgent is required (format: client-name/version, e.g., myapp/v1.0.0)")
	}
	if config.Organization == "" && len(config.PullRequests) == 0 {
		return nil, errors.New("organization or pull requests required")
	}
	if config.Token == "" && config.TokenProvider == nil {
		return nil, errors.New("token or tokenProvider is required")
	}

	// Set defaults
	if config.PingInterval == 0 {
		config.PingInterval = 30 * time.Second
	}
	if config.MaxBackoff == 0 {
		config.MaxBackoff = 2 * time.Minute // Use exponential backoff up to 2 minutes
	}

	// Set default logger if not provided
	logger := config.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	return &Client{
		config:              config,
		stopCh:              make(chan struct{}),
		stoppedCh:           make(chan struct{}),
		logger:              logger,
		commitPRCache:       make(map[string][]int),
		commitPRCacheExpiry: make(map[string]time.Time),
		commitCacheKeys:     make([]string, 0, defaultMaxCacheSize),
		maxCacheSize:        defaultMaxCacheSize,
		emptyResultTTL:      30 * time.Second, // Retry empty results after 30s
	}, nil
}

// Start begins the connection process with automatic reconnection.
func (c *Client) Start(ctx context.Context) error {
	defer close(c.stoppedCh)

	// Create retry options
	retryOpts := []retry.Option{
		retry.Context(ctx),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.MaxDelay(c.config.MaxBackoff),
		retry.OnRetry(func(n uint, err error) {
			c.mu.Lock()
			//nolint:gosec // Retry count will not overflow in practice
			c.retries = int(n)
			c.mu.Unlock()

			c.logger.Warn(separatorLine)
			c.logger.Warn("WebSocket CONNECTION LOST!", "error", err, "events_received", c.eventCount, "attempt", n+1)
			c.logger.Warn(separatorLine)

			// Notify disconnect callback
			if c.config.OnDisconnect != nil {
				c.config.OnDisconnect(err)
			}
		}),
		retry.RetryIf(func(err error) bool {
			// Don't retry authentication errors
			var authErr *AuthenticationError
			if errors.As(err, &authErr) {
				c.logger.Error(separatorLine)
				c.logger.Error("AUTHENTICATION FAILED!", "error", err)
				c.logger.Error("This is likely due to:")
				c.logger.Error("- Invalid GitHub token")
				c.logger.Error("- Not being a member of the requested organization")
				c.logger.Error("- Insufficient permissions")
				c.logger.Error(separatorLine)
				return false
			}

			// Don't retry if reconnection is disabled
			if c.config.NoReconnect {
				return false
			}

			// Don't retry if stop was requested
			select {
			case <-c.stopCh:
				return false
			default:
				return true
			}
		}),
	}

	// Configure retry attempts
	if c.config.MaxRetries > 0 {
		//nolint:gosec // MaxRetries is a user-configured value, overflow not a concern
		retryOpts = append(retryOpts, retry.Attempts(uint(c.config.MaxRetries)))
	} else {
		retryOpts = append(retryOpts, retry.UntilSucceeded())
	}

	// Use retry library to handle reconnection with exponential backoff and jitter
	return retry.Do(func() error {
		// Check for early cancellation - don't retry on shutdown
		select {
		case <-ctx.Done():
			c.logger.Info("Client context cancelled, shutting down")
			return retry.Unrecoverable(ctx.Err())
		case <-c.stopCh:
			c.logger.Info("Client stop requested")
			return retry.Unrecoverable(errors.New("stop requested"))
		default:
		}

		// Connection attempt logging
		c.mu.RLock()
		n := c.retries
		c.mu.RUnlock()

		if n == 0 {
			c.logger.Info("========================================")
			c.logger.Info("CONNECTING to WebSocket server", "url", c.config.ServerURL)
			c.logger.Info("========================================")
		} else {
			c.logger.Info("========================================")
			c.logger.Info("RECONNECTING to WebSocket server", "url", c.config.ServerURL, "attempt", n)
			c.logger.Info("========================================")
		}

		// Try to connect - this will run indefinitely if successful
		return c.connect(ctx)
	}, retryOpts...)
}

// Stop gracefully stops the client.
// Safe to call multiple times - only the first call will take effect.
// Also safe to call before Start() or if Start() was never called.
func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
		c.mu.Lock()
		if c.ws != nil {
			if closeErr := c.ws.Close(); closeErr != nil {
				c.logger.Error("Error closing websocket on shutdown", "error", closeErr)
			}
		}
		c.mu.Unlock()

		// Wait for Start() to finish, but with timeout in case Start() was never called
		select {
		case <-c.stoppedCh:
			// Start() completed normally
		case <-time.After(100 * time.Millisecond):
			// Start() was never called or hasn't started yet - that's ok
		}
	})
}

// connect establishes a WebSocket connection and handles events.
//
//nolint:funlen,maintidx // Connection lifecycle orchestration is inherently complex
func (c *Client) connect(ctx context.Context) error {
	c.logger.Info("Establishing WebSocket connection")

	// Get fresh token if TokenProvider is configured
	token := c.config.Token
	if c.config.TokenProvider != nil {
		t, err := c.config.TokenProvider()
		if err != nil {
			return fmt.Errorf("token provider: %w", err)
		}
		token = t
		c.logger.Debug("Using fresh token from TokenProvider")
	}

	// Create WebSocket config with appropriate origin
	origin := "http://localhost/"
	if strings.HasPrefix(c.config.ServerURL, "wss://") {
		origin = "https://localhost/"
	}
	wsConfig, err := websocket.NewConfig(c.config.ServerURL, origin)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Add Authorization and User-Agent headers
	wsConfig.Header = make(map[string][]string)
	wsConfig.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", token)}
	wsConfig.Header["User-Agent"] = []string{c.config.UserAgent}

	// Dial the server
	ws, err := websocket.DialConfig(wsConfig)
	if err != nil {
		return c.handleDialError(err)
	}
	c.logger.Info("========================================")
	c.logger.Info(fmt.Sprintf("✅ WebSocket ESTABLISHED: %s (org: %s)", c.config.ServerURL, c.config.Organization))
	c.logger.Info("========================================")

	// Store connection
	c.mu.Lock()
	c.ws = ws
	c.mu.Unlock()

	defer func() {
		c.logger.Info("========================================")
		c.logger.Info(fmt.Sprintf("❌ WebSocket CLOSING: %s (org: %s)", c.config.ServerURL, c.config.Organization))
		c.mu.Lock()
		c.ws = nil
		c.mu.Unlock()
		if err := ws.Close(); err != nil {
			c.logger.Error("Failed to close websocket cleanly", "error", err)
		} else {
			c.logger.Info("✓ WebSocket connection closed cleanly")
		}
		c.logger.Info("========================================")
	}()

	// Build subscription
	sub := map[string]any{
		"organization":     c.config.Organization,
		"user_events_only": c.config.UserEventsOnly,
	}

	// Add event types if specified
	if len(c.config.EventTypes) > 0 {
		// Check for wildcard
		if len(c.config.EventTypes) == 1 && c.config.EventTypes[0] == "*" {
			c.logger.Info("Subscribing to all event types")
			// Don't send event_types field - server interprets as all
		} else {
			sub["event_types"] = c.config.EventTypes
			c.logger.Info("Subscribing to event types", "types", c.config.EventTypes)
		}
	}

	// Add PR URLs if specified
	if len(c.config.PullRequests) > 0 {
		sub["pull_requests"] = c.config.PullRequests
		c.logger.Info("Subscribing to specific PRs", "count", len(c.config.PullRequests))
	}

	// Send subscription
	c.logger.Debug("Sending subscription request")
	if err := websocket.JSON.Send(ws, sub); err != nil {
		return fmt.Errorf("write subscription: %w", err)
	}
	c.logger.Debug("Waiting for subscription confirmation")

	// Set a short read deadline for subscription confirmation
	if err := ws.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read first response - should be either an error or subscription confirmation
	var firstResponse map[string]any
	if err := websocket.JSON.Receive(ws, &firstResponse); err != nil {
		return fmt.Errorf("failed to read subscription response (timeout after 2s): %w", err)
	}

	// Clear read deadline after successful read
	if err := ws.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("failed to clear read deadline: %w", err)
	}

	// Check response type
	responseType, ok := firstResponse[msgTypeField].(string)
	if !ok {
		responseType = ""
	}

	// Handle error response
	if responseType == "error" {
		errorCode, ok := firstResponse["error"].(string)
		if !ok {
			errorCode = ""
		}
		message, ok := firstResponse["message"].(string)
		if !ok {
			message = ""
		}
		c.logger.Error(separatorLine)
		c.logger.Error("SUBSCRIPTION REJECTED BY SERVER!", "error_code", errorCode, "message", message)
		c.logger.Error(separatorLine)

		// Return AuthenticationError for authentication/authorization errors to prevent retries
		if errorCode == "access_denied" || errorCode == "authentication_failed" {
			return &AuthenticationError{
				message: fmt.Sprintf("Authentication/authorization failed: %s", message),
			}
		}

		return fmt.Errorf("subscription rejected: %s - %s", errorCode, message)
	}

	// Handle subscription confirmation
	if responseType == "subscription_confirmed" {
		c.logger.Info("✓ Subscription confirmed by server!")
		if org, ok := firstResponse["organization"].(string); ok {
			if org == "*" {
				c.logger.Info("  Organization: * (all your organizations)")
			} else {
				c.logger.Info("  Subscription details", "organization", org)
			}
		}
		if username, ok := firstResponse["username"].(string); ok {
			c.logger.Info("  Subscription details", "username", username)
		}
		if eventTypes, ok := firstResponse["event_types"].([]any); ok && len(eventTypes) > 0 {
			types := make([]string, len(eventTypes))
			for i, t := range eventTypes {
				if s, ok := t.(string); ok {
					types[i] = s
				}
			}
			c.logger.Info("  Subscription details", "event_types", types)
		}
	} else {
		// For backward compatibility, treat any non-error response as success
		c.logger.Info("✓ Successfully subscribed", "response_type", responseType)
	}

	c.logger.Info("Listening for events...")

	// Notify connect callback
	if c.config.OnConnect != nil {
		c.config.OnConnect()
	}

	// Reset retry counter on successful connection
	c.mu.Lock()
	c.retries = 0
	c.mu.Unlock()

	// Create write channel for serializing all writes
	c.writeCh = make(chan any, writeChannelBuffer)

	// Start write pump - this is the ONLY goroutine that writes to the websocket
	writeCtx, cancelWrite := context.WithCancel(ctx)
	defer cancelWrite()
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- c.writePump(writeCtx, ws)
	}()

	// Start ping sender (sends to write channel, not directly to websocket)
	pingCtx, cancelPing := context.WithCancel(ctx)
	defer cancelPing()
	pingDone := make(chan struct{})
	go func() {
		c.sendPings(pingCtx)
		close(pingDone)
	}()

	// Read events - when this returns, cancel everything
	readErr := c.readEvents(ctx, ws)

	// Stop ping sender first - this ensures no more writes will be queued
	cancelPing()
	<-pingDone // Wait for ping sender to fully exit

	// Stop write pump
	cancelWrite()

	// Close write channel to signal writePump to exit cleanly
	// Safe to close now because ping sender has exited and won't write anymore
	close(c.writeCh)

	// Wait for write pump to finish
	writeErr := <-writeDone

	// Return the first error that occurred
	if readErr != nil {
		return readErr
	}
	return writeErr
}

// handleDialError checks for HTTP status codes in dial errors and returns appropriate errors.
func (*Client) handleDialError(err error) error {
	// Check for HTTP status codes in the error message
	s := err.Error()
	if !strings.Contains(s, "bad status") {
		return fmt.Errorf("dial: %w", err)
	}

	lower := strings.ToLower(s)
	// Extract status code if present
	if strings.Contains(s, "403") || strings.Contains(lower, "forbidden") {
		return &AuthenticationError{
			message: fmt.Sprintf(
				"Authentication failed (403 Forbidden): Check your GitHub token and organization membership. Original error: %v",
				err,
			),
		}
	}
	if strings.Contains(s, "401") || strings.Contains(lower, "unauthorized") {
		return &AuthenticationError{
			message: fmt.Sprintf("Authentication failed (401 Unauthorized): Invalid or missing token. Original error: %v", err),
		}
	}
	return fmt.Errorf("dial: %w", err)
}

// writePump is the ONLY goroutine that writes to the websocket.
// All writes must go through the writeCh channel to prevent concurrent writes.
func (c *Client) writePump(ctx context.Context, ws *websocket.Conn) error {
	const writeTimeout = 10 * time.Second

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case msg, ok := <-c.writeCh:
			if !ok {
				return errors.New("write channel closed")
			}

			// Set write deadline
			if err := ws.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				return fmt.Errorf("set write deadline: %w", err)
			}

			// Send message
			if err := websocket.JSON.Send(ws, msg); err != nil {
				return fmt.Errorf("write: %w", err)
			}
		}
	}
}

// sendPings sends periodic ping messages to keep the connection alive.
// Pings are sent to the write channel, not directly to the websocket.
func (c *Client) sendPings(ctx context.Context) {
	ticker := time.NewTicker(c.config.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ping := map[string]string{msgTypeField: "ping"}
			c.logger.Debug("[PING] Sending periodic ping to server")

			// Send to write channel (non-blocking)
			select {
			case c.writeCh <- ping:
				c.logger.Debug("[PING] ✓ Ping queued")
			case <-ctx.Done():
				return
			default:
				c.logger.Warn("[PING] Write channel full, skipping ping")
			}
		}
	}
}

// readEvents reads and processes events from the WebSocket with responsive shutdown.
//
//nolint:gocognit,revive,maintidx // Complex event processing with cache management is intentional and well-documented
func (c *Client) readEvents(ctx context.Context, ws *websocket.Conn) error {
	for {
		// Check for context cancellation first
		select {
		case <-ctx.Done():
			c.logger.Debug("readEvents: context cancelled, shutting down")
			return ctx.Err()
		default:
		}

		// Set read timeout for responsive shutdown
		if err := ws.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return fmt.Errorf("failed to set read timeout: %w", err)
		}

		// Receive message
		var response map[string]any
		err := websocket.JSON.Receive(ws, &response)
		if err != nil {
			// Check if it's a timeout error - may be normal during shutdown
			if strings.Contains(err.Error(), "i/o timeout") {
				// Check context again after timeout
				select {
				case <-ctx.Done():
					c.logger.Debug("readEvents: context cancelled during timeout, shutting down")
					return ctx.Err()
				default:
					// Continue reading if context is still active
					continue
				}
			}

			c.logger.Error(separatorLine)
			c.logger.Error("Lost connection while reading!", "error", err, "events_received", c.eventCount)
			c.logger.Error(separatorLine)
			return fmt.Errorf("read: %w", err)
		}

		// Check message type
		responseType, ok := response[msgTypeField].(string)
		if !ok {
			responseType = ""
		}

		// Handle ping messages from server
		if responseType == "ping" {
			c.logger.Debug("[PONG] Received PING from server")

			// Build pong response
			pong := map[string]any{msgTypeField: "pong"}
			if seq, ok := response["seq"]; ok {
				pong["seq"] = seq
			}

			// Send pong via write channel (non-blocking with timeout)
			select {
			case c.writeCh <- pong:
				c.logger.Debug("[PONG] Sent PONG response to server", "seq", pong["seq"])
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(1 * time.Second):
				c.logger.Error("[PONG] Failed to queue pong - write channel blocked")
				return errors.New("pong send blocked")
			}
			continue
		}

		// Handle pong acknowledgments from server
		if responseType == "pong" {
			c.logger.Debug("[PONG] Received PONG acknowledgment from server")
			continue
		}

		// Process the event inline
		event := Event{
			Type: responseType,
			Raw:  response,
		}

		if url, ok := response["url"].(string); ok {
			event.URL = url
		}

		if ts, ok := response["timestamp"].(string); ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				event.Timestamp = t
			}
		}

		if deliveryID, ok := response["delivery_id"].(string); ok {
			event.DeliveryID = deliveryID
		}

		if commitSHA, ok := response["commit_sha"].(string); ok {
			event.CommitSHA = commitSHA
		}

		c.mu.Lock()
		c.eventCount++
		eventNum := c.eventCount
		c.mu.Unlock()

		// Populate cache from pull_request events to prevent cache misses
		// This ensures check events arriving shortly after PR creation can find the PR
		//nolint:nestif // Cache population logic requires nested validation
		if event.Type == "pull_request" && event.CommitSHA != "" && strings.Contains(event.URL, "/pull/") {
			// Extract owner/repo/pr_number from URL
			parts := strings.Split(event.URL, "/")
			if len(parts) >= 7 && parts[2] == "github.com" && parts[5] == "pull" {
				owner := parts[3]
				repo := parts[4]
				prNum, err := strconv.Atoi(parts[6])
				if err == nil && prNum > 0 {
					key := owner + "/" + repo + ":" + event.CommitSHA

					c.cacheMu.Lock()
					// Check if cache entry exists
					existing, exists := c.commitPRCache[key]
					if !exists {
						// Ensure cache has space before adding new entry
						c.ensureCacheSpace()

						// New cache entry
						c.commitCacheKeys = append(c.commitCacheKeys, key)
						c.commitPRCache[key] = []int{prNum}
						c.logger.Debug("Populated cache from pull_request event",
							"commit_sha", event.CommitSHA,
							"owner", owner,
							"repo", repo,
							"pr_number", prNum)
					} else {
						// Check if PR number already in list
						found := false
						for _, existingPR := range existing {
							if existingPR == prNum { //nolint:revive // PR deduplication requires nested check
								found = true
								break
							}
						}
						if !found { //nolint:revive // Cache update requires nested check
							// Add PR to existing cache entry
							c.commitPRCache[key] = append(existing, prNum)
							c.logger.Debug("Added PR to existing cache entry",
								"commit_sha", event.CommitSHA,
								"owner", owner,
								"repo", repo,
								"pr_number", prNum,
								"total_prs", len(c.commitPRCache[key]))
						}
					}
					c.cacheMu.Unlock()
				}
			}
		}

		// Handle check events with repo-only URLs (GitHub race condition)
		// Automatically expand into per-PR events using GitHub API with caching
		//nolint:nestif // Check event expansion requires nested validation and cache management
		if (event.Type == "check_run" || event.Type == "check_suite") && event.CommitSHA != "" && !strings.Contains(event.URL, "/pull/") {
			// Extract owner/repo from URL
			parts := strings.Split(event.URL, "/")
			if len(parts) >= 5 && parts[2] == "github.com" {
				owner := parts[3]
				repo := parts[4]
				key := owner + "/" + repo + ":" + event.CommitSHA

				// Check cache first
				c.cacheMu.RLock()
				cached, cacheExists := c.commitPRCache[key]
				expiry, hasExpiry := c.commitPRCacheExpiry[key]
				c.cacheMu.RUnlock()

				// Check if cached empty result has expired (need to re-query GitHub)
				cacheExpired := cacheExists && len(cached) == 0 && hasExpiry && time.Now().After(expiry)

				var prs []int
				if cacheExists && !cacheExpired {
					// Cache hit - return copy to prevent external modifications
					prs = make([]int, len(cached))
					copy(prs, cached)
					c.logger.Info("Check event with repo URL - using cached PR lookup",
						"commit_sha", event.CommitSHA,
						"repo_url", event.URL,
						"type", event.Type,
						"pr_count", len(prs),
						"cache_hit", true)
				} else {
					// Cache miss or expired empty result - look up via GitHub API
					if cacheExpired {
						c.logger.Info("Cached empty result expired - retrying GitHub API",
							"commit_sha", event.CommitSHA,
							"repo_url", event.URL,
							"type", event.Type)
					}
					c.logger.Info("Check event with repo URL - looking up PRs via GitHub API",
						"commit_sha", event.CommitSHA,
						"repo_url", event.URL,
						"type", event.Type,
						"cache_hit", false)

					gh := github.NewClient(c.config.Token, c.logger)
					var err error
					prs, err = gh.FindPRsForCommit(ctx, owner, repo, event.CommitSHA)
					if err != nil {
						c.logger.Warn("Failed to look up PRs for commit",
							"commit_sha", event.CommitSHA,
							"owner", owner,
							"repo", repo,
							"error", err)
						// Don't cache errors - try again next time
					} else {
						// Cache the result (even if empty)
						c.cacheMu.Lock()
						if _, exists := c.commitPRCache[key]; !exists { //nolint:revive // Cache management requires nested check
							// Ensure cache has space before adding new entry
							c.ensureCacheSpace()
							c.commitCacheKeys = append(c.commitCacheKeys, key)
						}
						// Store copy to prevent external modifications
						cachedPRs := make([]int, len(prs))
						copy(cachedPRs, prs)
						c.commitPRCache[key] = cachedPRs
						// Set TTL for empty results so we retry after indexing delay
						if len(prs) == 0 {
							c.commitPRCacheExpiry[key] = time.Now().Add(c.emptyResultTTL)
						} else {
							// Remove any expiry for non-empty results (cache permanently until evicted)
							delete(c.commitPRCacheExpiry, key)
						}
						c.cacheMu.Unlock()

						if len(prs) == 0 {
							c.logger.Info("Cached empty PR lookup result with TTL",
								"commit_sha", event.CommitSHA,
								"ttl_seconds", int(c.emptyResultTTL.Seconds()))
						} else {
							c.logger.Info("Cached PR lookup result",
								"commit_sha", event.CommitSHA,
								"pr_count", len(prs))
						}
					}
				}

				// Emit events for each PR found
				if len(prs) > 0 {
					for _, n := range prs {
						e := event // Copy the event
						e.URL = fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, repo, n)

						if c.config.OnEvent != nil {
							c.logger.Info("Event received (expanded from commit)",
								"timestamp", e.Timestamp.Format("15:04:05"),
								"event_number", eventNum,
								"type", e.Type,
								"url", e.URL,
								"commit_sha", e.CommitSHA,
								"delivery_id", e.DeliveryID)
							c.config.OnEvent(e)
						}
					}
					continue // Skip the normal event handling since we expanded it
				}
				c.logger.Info("No PRs found for commit - may be push to main",
					"commit_sha", event.CommitSHA,
					"owner", owner,
					"repo", repo)
			}
		}

		// Log event
		if c.config.Verbose {
			c.logger.Info("Event received",
				"event_number", eventNum,
				"timestamp", event.Timestamp.Format("15:04:05"),
				"type", event.Type,
				"url", event.URL,
				"commit_sha", event.CommitSHA,
				"delivery_id", event.DeliveryID,
				"raw", event.Raw)
		} else {
			if event.Type != "" && event.URL != "" {
				c.logger.Info("Event received",
					"timestamp", event.Timestamp.Format("15:04:05"),
					"event_number", eventNum,
					"type", event.Type,
					"url", event.URL,
					"commit_sha", event.CommitSHA,
					"delivery_id", event.DeliveryID)
			} else {
				c.logger.Info("Event received",
					"timestamp", event.Timestamp.Format("15:04:05"),
					"event_number", eventNum,
					"delivery_id", event.DeliveryID,
					"response", response)
			}
		}

		if c.config.OnEvent != nil {
			c.config.OnEvent(event)
		}
	}
}

// ensureCacheSpace evicts old cache entries if needed to prevent unbounded growth.
// Must be called with cacheMu locked.
// Implements two-tier eviction:
//   - Soft limit (defaultMaxCacheSize): evict 25% of entries
//   - Hard limit (hardMaxCacheSize): aggressive eviction of 50% of entries
func (c *Client) ensureCacheSpace() {
	n := len(c.commitCacheKeys)

	var evict int
	switch {
	case n >= hardMaxCacheSize:
		// Hit hard limit - aggressive eviction (50%)
		evict = hardMaxCacheSize / 2
		c.logger.Warn("Cache hit hard limit, performing aggressive eviction",
			"current_size", n,
			"hard_limit", hardMaxCacheSize,
			"evicting", evict)
	case n >= c.maxCacheSize:
		// Hit soft limit - normal eviction (25%)
		evict = c.maxCacheSize / 4
		c.logger.Debug("Cache hit soft limit, performing normal eviction",
			"current_size", n,
			"soft_limit", c.maxCacheSize,
			"evicting", evict)
	default:
		return
	}

	// Evict oldest entries
	for i := range evict {
		delete(c.commitPRCache, c.commitCacheKeys[i])
		delete(c.commitPRCacheExpiry, c.commitCacheKeys[i])
	}
	c.commitCacheKeys = c.commitCacheKeys[evict:]
}
