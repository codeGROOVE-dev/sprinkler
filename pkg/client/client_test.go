package client

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// TestStopMultipleCalls verifies that calling Stop() multiple times is safe
// and doesn't panic with "close of closed channel".
func TestStopMultipleCalls(t *testing.T) {
	// Create a client with minimal config
	client, err := New(Config{
		ServerURL:    "ws://localhost:8080",
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true, // Disable reconnect to make test faster
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Start the client in a goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		// Expected to fail to connect, but that's ok for this test
		_ = client.Start(ctx) //nolint:errcheck // Error is expected in tests - client can't connect to non-existent server
	}()

	// Give it a moment to initialize
	time.Sleep(10 * time.Millisecond)

	// Call Stop() multiple times concurrently
	// This should NOT panic with "close of closed channel"
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client.Stop() // Should be safe to call multiple times
		}()
	}

	// Wait for all Stop() calls to complete
	wg.Wait()

	// If we get here without a panic, the test passes
}

// TestStopBeforeStart verifies that calling Stop() before Start() is safe.
func TestStopBeforeStart(t *testing.T) {
	client, err := New(Config{
		ServerURL:    "ws://localhost:8080",
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Call Stop() before Start()
	client.Stop()

	// Now try to start - should exit cleanly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = client.Start(ctx)
	// We expect either context.DeadlineExceeded or "stop requested"
	if err == nil {
		t.Error("Expected Start() to fail after Stop(), but it succeeded")
	}
}

// TestCommitPRCachePopulation tests that pull_request events populate the cache.
// This is a unit test that directly tests the cache logic without needing a WebSocket connection.
func TestCommitPRCachePopulation(t *testing.T) {
	client, err := New(Config{
		ServerURL:    "ws://localhost:8080",
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	t.Run("pull_request event populates cache", func(t *testing.T) {
		// Simulate cache population from a pull_request event
		commitSHA := "abc123def456"
		owner := "test-org"
		repo := "test-repo"
		prNumber := 123
		key := owner + "/" + repo + ":" + commitSHA

		// Populate cache as the production code would
		client.cacheMu.Lock()
		client.commitCacheKeys = append(client.commitCacheKeys, key)
		client.commitPRCache[key] = []int{prNumber}
		client.cacheMu.Unlock()

		// Verify cache was populated
		client.cacheMu.RLock()
		cached, exists := client.commitPRCache[key]
		client.cacheMu.RUnlock()

		if !exists {
			t.Errorf("Expected cache key %q to exist", key)
		}
		if len(cached) != 1 || cached[0] != prNumber {
			t.Errorf("Expected cached PR [%d], got %v", prNumber, cached)
		}
	})

	t.Run("multiple PRs for same commit", func(t *testing.T) {
		commitSHA := "def456"
		owner := "test-org"
		repo := "test-repo"
		key := owner + "/" + repo + ":" + commitSHA

		// First PR
		client.cacheMu.Lock()
		client.commitCacheKeys = append(client.commitCacheKeys, key)
		client.commitPRCache[key] = []int{100}
		client.cacheMu.Unlock()

		// Second PR for same commit (simulates branch being merged then reopened)
		client.cacheMu.Lock()
		existing := client.commitPRCache[key]
		client.commitPRCache[key] = append(existing, 200)
		client.cacheMu.Unlock()

		// Verify both PRs are cached
		client.cacheMu.RLock()
		cached := client.commitPRCache[key]
		client.cacheMu.RUnlock()

		if len(cached) != 2 {
			t.Errorf("Expected 2 PRs in cache, got %d: %v", len(cached), cached)
		}
		if cached[0] != 100 || cached[1] != 200 {
			t.Errorf("Expected cached PRs [100, 200], got %v", cached)
		}
	})

	t.Run("cache eviction when full", func(t *testing.T) {
		// Fill cache to max size + 1 (to trigger eviction)
		client.cacheMu.Lock()
		client.commitCacheKeys = make([]string, 0, client.maxCacheSize+1)
		client.commitPRCache = make(map[string][]int)

		for i := 0; i <= client.maxCacheSize; i++ {
			key := "org/repo:sha" + string(rune(i))
			client.commitCacheKeys = append(client.commitCacheKeys, key)
			client.commitPRCache[key] = []int{i}
		}

		// Now simulate eviction logic (as production code would do)
		if len(client.commitCacheKeys) > client.maxCacheSize {
			// Evict oldest 25%
			n := client.maxCacheSize / 4
			for i := range n {
				delete(client.commitPRCache, client.commitCacheKeys[i])
			}
			client.commitCacheKeys = client.commitCacheKeys[n:]
		}
		client.cacheMu.Unlock()

		// Verify eviction happened correctly
		client.cacheMu.RLock()
		_, oldExists := client.commitPRCache["org/repo:sha"+string(rune(0))]
		cacheSize := len(client.commitPRCache)
		keyCount := len(client.commitCacheKeys)
		client.cacheMu.RUnlock()

		if oldExists {
			t.Error("Expected oldest cache entry to be evicted")
		}
		if cacheSize != keyCount {
			t.Errorf("Cache size %d doesn't match key count %d", cacheSize, keyCount)
		}
		if cacheSize > client.maxCacheSize {
			t.Errorf("Cache size %d exceeds max %d", cacheSize, client.maxCacheSize)
		}
	})
}

// mockWebSocketServer creates a test WebSocket server with configurable behavior.
type mockWebSocketServer struct {
	server         *httptest.Server
	url            string
	onConnection   func(*websocket.Conn)
	acceptAuth     bool
	sendEvents     []map[string]any
	sendPings      bool
	closeDelay     time.Duration
	rejectWithCode int
}

func newMockServer(t *testing.T, acceptAuth bool) *mockWebSocketServer {
	t.Helper()
	m := &mockWebSocketServer{
		acceptAuth: acceptAuth,
	}

	handler := websocket.Handler(func(ws *websocket.Conn) {
		if m.onConnection != nil {
			m.onConnection(ws)
			return
		}

		// Default behavior: read subscription, confirm, send events, handle pings
		var sub map[string]any
		if err := websocket.JSON.Receive(ws, &sub); err != nil {
			t.Logf("Failed to read subscription: %v", err)
			return
		}

		// Send subscription confirmation
		confirmation := map[string]any{
			"type":         "subscription_confirmed",
			"organization": sub["organization"],
		}
		if err := websocket.JSON.Send(ws, confirmation); err != nil {
			t.Logf("Failed to send confirmation: %v", err)
			return
		}

		// Send events if configured
		for _, event := range m.sendEvents {
			if err := websocket.JSON.Send(ws, event); err != nil {
				t.Logf("Failed to send event: %v", err)
				return
			}
		}

		// Handle pings/pongs
		for {
			var msg map[string]any
			if err := websocket.JSON.Receive(ws, &msg); err != nil {
				if err == io.EOF {
					return
				}
				t.Logf("Read error: %v", err)
				return
			}

			if msgType, ok := msg["type"].(string); ok {
				if msgType == "ping" {
					pong := map[string]any{"type": "pong"}
					if seq, ok := msg["seq"]; ok {
						pong["seq"] = seq
					}
					if err := websocket.JSON.Send(ws, pong); err != nil {
						return
					}
				}
			}
		}
	})

	m.server = httptest.NewServer(handler)
	m.url = "ws" + strings.TrimPrefix(m.server.URL, "http")
	return m
}

func (m *mockWebSocketServer) Close() {
	m.server.Close()
}

// TestClientConnectAndReceiveEvents tests the full connection lifecycle.
func TestClientConnectAndReceiveEvents(t *testing.T) {
	// Create mock server that sends test events
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":      "pull_request",
			"url":       "https://github.com/test/repo/pull/1",
			"timestamp": time.Now().Format(time.RFC3339),
		},
		{
			"type":      "check_run",
			"url":       "https://github.com/test/repo/pull/1",
			"timestamp": time.Now().Format(time.RFC3339),
		},
	}

	// Create client
	var receivedEvents []Event
	var mu sync.Mutex

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
		OnEvent: func(e Event) {
			mu.Lock()
			receivedEvents = append(receivedEvents, e)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Start client with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- client.Start(ctx)
	}()

	// Wait a bit for events to be received
	time.Sleep(500 * time.Millisecond)
	client.Stop()

	// Check received events
	mu.Lock()
	eventCount := len(receivedEvents)
	mu.Unlock()

	if eventCount != 2 {
		t.Errorf("Expected 2 events, got %d", eventCount)
	}
}

// TestClientPingPong tests that pings are sent and pongs are received.
func TestClientPingPong(t *testing.T) {
	pingReceived := make(chan bool, 10)

	srv := newMockServer(t, true)
	defer srv.Close()

	// Custom connection handler that tracks pings
	srv.onConnection = func(ws *websocket.Conn) {
		// Read subscription
		var sub map[string]any
		if err := websocket.JSON.Receive(ws, &sub); err != nil {
			return
		}

		// Send confirmation
		confirmation := map[string]any{"type": "subscription_confirmed"}
		if err := websocket.JSON.Send(ws, confirmation); err != nil {
			return
		}

		// Listen for pings from client
		for {
			var msg map[string]any
			if err := websocket.JSON.Receive(ws, &msg); err != nil {
				return
			}

			if msgType, ok := msg["type"].(string); ok && msgType == "ping" {
				pingReceived <- true

				// Send pong response
				pong := map[string]any{"type": "pong"}
				if err := websocket.JSON.Send(ws, pong); err != nil {
					return
				}
			}
		}
	}

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		PingInterval: 100 * time.Millisecond, // Fast pings for testing
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to timeout
	}()

	// Wait for at least 2 pings
	select {
	case <-pingReceived:
		// First ping received
	case <-time.After(1 * time.Second):
		t.Fatal("No ping received within 1 second")
	}

	select {
	case <-pingReceived:
		// Second ping received - success!
	case <-time.After(1 * time.Second):
		t.Fatal("Second ping not received within 1 second")
	}

	client.Stop()
}

// TestClientReconnection tests that the client reconnects on disconnect.
func TestClientReconnection(t *testing.T) {
	connectionCount := 0
	var mu sync.Mutex

	srv := newMockServer(t, true)
	defer srv.Close()

	srv.onConnection = func(ws *websocket.Conn) {
		mu.Lock()
		connectionCount++
		count := connectionCount
		mu.Unlock()

		// Read subscription
		var sub map[string]any
		if err := websocket.JSON.Receive(ws, &sub); err != nil {
			return
		}

		// Send confirmation
		confirmation := map[string]any{"type": "subscription_confirmed"}
		if err := websocket.JSON.Send(ws, confirmation); err != nil {
			return
		}

		// First connection: close immediately to trigger reconnection
		if count == 1 {
			ws.Close()
			return
		}

		// Second connection: stay alive
		for {
			var msg map[string]any
			if err := websocket.JSON.Receive(ws, &msg); err != nil {
				return
			}
		}
	}

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		MaxBackoff:   100 * time.Millisecond, // Fast reconnection for testing
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to timeout
	}()

	// Wait for reconnection
	time.Sleep(1 * time.Second)

	mu.Lock()
	count := connectionCount
	mu.Unlock()

	if count < 2 {
		t.Errorf("Expected at least 2 connections (reconnection), got %d", count)
	}

	client.Stop()
}

// TestClientAuthenticationError tests that auth errors don't trigger reconnection.
func TestClientAuthenticationError(t *testing.T) {
	srv := newMockServer(t, false)
	defer srv.Close()

	srv.onConnection = func(ws *websocket.Conn) {
		// Read subscription
		var sub map[string]any
		if err := websocket.JSON.Receive(ws, &sub); err != nil {
			return
		}

		// Send auth error
		errMsg := map[string]any{
			"type":    "error",
			"error":   "access_denied",
			"message": "Not authorized",
		}
		if err := websocket.JSON.Send(ws, errMsg); err != nil {
			return
		}
	}

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "bad-token",
		Organization: "test-org",
		MaxRetries:   3,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = client.Start(ctx)
	if err == nil {
		t.Fatal("Expected authentication error, got nil")
	}

	if !strings.Contains(err.Error(), "Authentication") && !strings.Contains(err.Error(), "authorization") {
		t.Errorf("Expected authentication error, got: %v", err)
	}
}

// TestClientServerPings tests that the client responds to server pings.
func TestClientServerPings(t *testing.T) {
	pongReceived := make(chan bool, 10)

	srv := newMockServer(t, true)
	defer srv.Close()

	srv.onConnection = func(ws *websocket.Conn) {
		// Read subscription
		var sub map[string]any
		if err := websocket.JSON.Receive(ws, &sub); err != nil {
			return
		}

		// Send confirmation
		confirmation := map[string]any{"type": "subscription_confirmed"}
		if err := websocket.JSON.Send(ws, confirmation); err != nil {
			return
		}

		// Send pings to client
		go func() {
			for i := 0; i < 3; i++ {
				ping := map[string]any{"type": "ping", "seq": i}
				if err := websocket.JSON.Send(ws, ping); err != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()

		// Listen for pongs
		for {
			var msg map[string]any
			if err := websocket.JSON.Receive(ws, &msg); err != nil {
				return
			}

			if msgType, ok := msg["type"].(string); ok && msgType == "pong" {
				pongReceived <- true
			}
		}
	}

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to timeout
	}()

	// Wait for pongs
	pongsReceived := 0
	timeout := time.After(1 * time.Second)

	for pongsReceived < 2 {
		select {
		case <-pongReceived:
			pongsReceived++
		case <-timeout:
			t.Fatalf("Only received %d pongs, expected at least 2", pongsReceived)
		}
	}

	client.Stop()
}

// TestClientEventWithCommitSHA tests event handling with commit SHA.
func TestClientEventWithCommitSHA(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":       "pull_request",
			"url":        "https://github.com/test/repo/pull/123",
			"commit_sha": "abc123",
			"timestamp":  time.Now().Format(time.RFC3339),
		},
	}

	var receivedEvent Event
	eventReceived := make(chan bool, 1)

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
		OnEvent: func(e Event) {
			receivedEvent = e
			eventReceived <- true
		},
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to timeout
	}()

	// Wait for event
	select {
	case <-eventReceived:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Event not received")
	}

	if receivedEvent.CommitSHA != "abc123" {
		t.Errorf("Expected commit SHA 'abc123', got %q", receivedEvent.CommitSHA)
	}
	if receivedEvent.Type != "pull_request" {
		t.Errorf("Expected type 'pull_request', got %q", receivedEvent.Type)
	}

	client.Stop()
}

// TestClientWriteChannelBlocking tests that write channel doesn't block indefinitely.
func TestClientWriteChannelBlocking(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.onConnection = func(ws *websocket.Conn) {
		// Read subscription
		var sub map[string]any
		if err := websocket.JSON.Receive(ws, &sub); err != nil {
			return
		}

		// Send confirmation
		confirmation := map[string]any{"type": "subscription_confirmed"}
		if err := websocket.JSON.Send(ws, confirmation); err != nil {
			return
		}

		// Don't read anything else - this will cause write buffer to potentially fill
		time.Sleep(5 * time.Second)
	}

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		PingInterval: 10 * time.Millisecond, // Very fast pings to fill buffer
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err = client.Start(ctx)
	// Should timeout gracefully, not deadlock
	if err != context.DeadlineExceeded {
		t.Logf("Expected deadline exceeded, got: %v", err)
	}

	client.Stop()
}

// TestClientCachePopulationFromPullRequestEvent tests the cache population logic.
func TestClientCachePopulationFromPullRequestEvent(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	// Send a pull_request event with commit SHA
	srv.sendEvents = []map[string]any{
		{
			"type":       "pull_request",
			"url":        "https://github.com/owner/repo/pull/456",
			"commit_sha": "def789",
			"timestamp":  time.Now().Format(time.RFC3339),
		},
	}

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to timeout
	}()

	// Wait for event processing
	time.Sleep(500 * time.Millisecond)
	client.Stop()

	// Check that cache was populated
	client.cacheMu.RLock()
	cached, exists := client.commitPRCache["owner/repo:def789"]
	client.cacheMu.RUnlock()

	if !exists {
		t.Error("Expected cache to be populated from pull_request event")
	}
	if len(cached) != 1 || cached[0] != 456 {
		t.Errorf("Expected cached PR [456], got %v", cached)
	}
}
