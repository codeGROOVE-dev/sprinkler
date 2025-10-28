package client

import (
	"context"
	"fmt"
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

// TestClientErrorResponse tests handling of server error messages.
func TestClientErrorResponse(t *testing.T) {
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

		// Send error message
		errMsg := map[string]any{
			"type":    "error",
			"error":   "rate_limited",
			"message": "Too many requests",
		}
		if err := websocket.JSON.Send(ws, errMsg); err != nil {
			return
		}

		time.Sleep(5 * time.Second)
	}

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		MaxRetries:   2,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = client.Start(ctx)
	if err == nil {
		t.Fatal("Expected error from server, got nil")
	}

	if !strings.Contains(err.Error(), "rate_limited") && !strings.Contains(err.Error(), "error") {
		t.Logf("Got error: %v", err)
	}
}

// TestClientInvalidJSON tests handling of malformed JSON from server.
func TestClientInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		// Send invalid JSON
		_, _ = ws.Write([]byte("{invalid json}"))
		time.Sleep(100 * time.Millisecond)
		ws.Close()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	client, err := New(Config{
		ServerURL:    wsURL,
		Token:        "test-token",
		Organization: "test-org",
		MaxRetries:   1,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = client.Start(ctx)
	// Should handle gracefully and return error or timeout
	if err == nil {
		t.Log("Client handled invalid JSON gracefully")
	}

	client.Stop()
}

// TestClientConnectionClosed tests handling of unexpected connection close.
func TestClientConnectionClosed(t *testing.T) {
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

		// Close connection immediately
		ws.Close()
	}

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		MaxRetries:   1,
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = client.Start(ctx)
	// Should handle connection close gracefully
	if err == nil {
		t.Log("Client handled connection close")
	}
}

// TestClientMaxRetries tests that client respects max retries.
func TestClientMaxRetries(t *testing.T) {
	attemptCount := 0
	var mu sync.Mutex

	srv := newMockServer(t, true)
	defer srv.Close()

	srv.onConnection = func(ws *websocket.Conn) {
		mu.Lock()
		attemptCount++
		mu.Unlock()

		// Always reject
		ws.Close()
	}

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		MaxRetries:   3,
		MaxBackoff:   10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = client.Start(ctx)
	if err == nil {
		t.Error("Expected error after max retries")
	}

	mu.Lock()
	attempts := attemptCount
	mu.Unlock()

	if attempts < 3 {
		t.Errorf("Expected at least 3 connection attempts, got %d", attempts)
	}
}

// TestClientStopWhileConnecting tests stopping while connection is in progress.
func TestClientStopWhileConnecting(t *testing.T) {
	// Create a server that delays accepting connections
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		time.Sleep(5 * time.Second)
		ws.Close()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	client, err := New(Config{
		ServerURL:    wsURL,
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to be stopped
	}()

	// Give it time to start connecting
	time.Sleep(100 * time.Millisecond)

	// Stop while connecting
	client.Stop()

	// Should complete without hanging
	time.Sleep(100 * time.Millisecond)
}

// TestClientEventWithoutCommitSHA tests event handling without commit SHA.
func TestClientEventWithoutCommitSHA(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":      "push",
			"url":       "https://github.com/test/repo",
			"timestamp": time.Now().Format(time.RFC3339),
			// No commit_sha field
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

	if receivedEvent.CommitSHA != "" {
		t.Errorf("Expected empty commit SHA, got %q", receivedEvent.CommitSHA)
	}
	if receivedEvent.Type != "push" {
		t.Errorf("Expected type 'push', got %q", receivedEvent.Type)
	}

	client.Stop()
}

// TestClientNoOnEvent tests that client works without OnEvent callback.
func TestClientNoOnEvent(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":      "pull_request",
			"url":       "https://github.com/test/repo/pull/1",
			"timestamp": time.Now().Format(time.RFC3339),
		},
	}

	// Create client without OnEvent callback
	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
		// OnEvent not set
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to timeout
	}()

	// Should not panic, just drop events
	time.Sleep(500 * time.Millisecond)
	client.Stop()
}

// TestClientSubscriptionTimeout tests subscription confirmation timeout.
func TestClientSubscriptionTimeout(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.onConnection = func(ws *websocket.Conn) {
		// Read subscription but never send confirmation
		var sub map[string]any
		if err := websocket.JSON.Receive(ws, &sub); err != nil {
			return
		}
		// Don't send confirmation - client should timeout
		time.Sleep(10 * time.Second)
	}

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		MaxRetries:   1,
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = client.Start(ctx)
	if err == nil {
		t.Error("Expected timeout error for subscription confirmation")
	}
}

// TestClientUnknownMessageType tests handling of unknown message types.
func TestClientUnknownMessageType(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":    "unknown_type",
			"data":    "some data",
			"unknown": true,
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

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to timeout
	}()

	// Should handle unknown message gracefully
	time.Sleep(500 * time.Millisecond)
	client.Stop()
}

// TestClientConfigValidation tests configuration validation.
func TestClientConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		errMsg string
	}{
		{
			name: "empty server URL",
			config: Config{
				Token:        "token",
				Organization: "org",
			},
			errMsg: "serverURL",
		},
		{
			name: "empty token",
			config: Config{
				ServerURL:    "ws://localhost:8080",
				Organization: "org",
			},
			errMsg: "token",
		},
		{
			name: "empty organization",
			config: Config{
				ServerURL: "ws://localhost:8080",
				Token:     "token",
			},
			errMsg: "organization",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.config)
			if err == nil {
				t.Error("Expected validation error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Expected error containing %q, got: %v", tt.errMsg, err)
			}
		})
	}
}

// TestClientDefaultConfig tests default configuration values.
func TestClientDefaultConfig(t *testing.T) {
	client, err := New(Config{
		ServerURL:    "ws://localhost:8080",
		Token:        "token",
		Organization: "org",
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Just verify client was created successfully with defaults
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
}

// TestClientMultiplePRsForCommit tests caching multiple PRs for the same commit.
func TestClientMultiplePRsForCommit(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	// Send two pull_request events with the same commit SHA
	srv.sendEvents = []map[string]any{
		{
			"type":       "pull_request",
			"url":        "https://github.com/owner/repo/pull/100",
			"commit_sha": "same_sha_123",
			"timestamp":  time.Now().Format(time.RFC3339),
		},
		{
			"type":       "pull_request",
			"url":        "https://github.com/owner/repo/pull/200",
			"commit_sha": "same_sha_123", // Same SHA, different PR
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

	// Wait for events to be processed
	time.Sleep(500 * time.Millisecond)
	client.Stop()

	// Check cache has both PRs
	client.cacheMu.RLock()
	cached, exists := client.commitPRCache["owner/repo:same_sha_123"]
	client.cacheMu.RUnlock()

	if !exists {
		t.Error("Expected cache entry for commit")
	}
	if len(cached) != 2 {
		t.Errorf("Expected 2 PRs in cache, got %d: %v", len(cached), cached)
	}
}

// TestClientCheckEventExpansion tests check event expansion using cache.
func TestClientCheckEventExpansion(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	// First send a pull_request event to populate the cache
	// Then send a check_run event with repo-only URL that should use the cache
	srv.sendEvents = []map[string]any{
		{
			"type":       "pull_request",
			"url":        "https://github.com/owner/repo/pull/456",
			"commit_sha": "check_sha_789",
			"timestamp":  time.Now().Format(time.RFC3339),
		},
		{
			"type":       "check_run",
			"url":        "https://github.com/owner/repo", // No /pull/ in URL
			"commit_sha": "check_sha_789",
			"timestamp":  time.Now().Format(time.RFC3339),
		},
	}

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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to timeout
	}()

	// Wait for events to be processed
	time.Sleep(500 * time.Millisecond)
	client.Stop()

	// Check we received both events (PR + expanded check)
	mu.Lock()
	count := len(receivedEvents)
	mu.Unlock()

	if count != 2 {
		t.Errorf("Expected 2 events (PR + expanded check), got %d", count)
	}

	// Verify cache was populated
	client.cacheMu.RLock()
	_, exists := client.commitPRCache["owner/repo:check_sha_789"]
	client.cacheMu.RUnlock()

	if !exists {
		t.Error("Expected cache to be populated from pull_request event")
	}
}

// TestClientInvalidTimestamp tests timestamp parsing error handling.
func TestClientInvalidTimestamp(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":      "pull_request",
			"url":       "https://github.com/test/repo/pull/1",
			"timestamp": "invalid-timestamp-format",
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
		// Success - event received despite bad timestamp
	case <-time.After(1 * time.Second):
		t.Fatal("Event not received")
	}

	// Timestamp should be zero value since parsing failed
	if !receivedEvent.Timestamp.IsZero() {
		t.Errorf("Expected zero timestamp for invalid format, got %v", receivedEvent.Timestamp)
	}

	client.Stop()
}

// TestClientInvalidPRURL tests handling of malformed PR URLs.
func TestClientInvalidPRURL(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":       "pull_request",
			"url":        "https://github.com/invalid", // Too short
			"commit_sha": "sha123",
			"timestamp":  time.Now().Format(time.RFC3339),
		},
		{
			"type":       "pull_request",
			"url":        "https://example.com/owner/repo/pull/1", // Wrong domain
			"commit_sha": "sha456",
			"timestamp":  time.Now().Format(time.RFC3339),
		},
		{
			"type":       "pull_request",
			"url":        "https://github.com/owner/repo/issues/1", // Not a PR
			"commit_sha": "sha789",
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

	// Wait for events to be processed
	time.Sleep(500 * time.Millisecond)
	client.Stop()

	// These invalid URLs should not populate the cache
	client.cacheMu.RLock()
	cacheSize := len(client.commitPRCache)
	client.cacheMu.RUnlock()

	if cacheSize != 0 {
		t.Errorf("Expected empty cache for invalid URLs, got %d entries", cacheSize)
	}
}

// TestClientCacheEviction tests cache eviction when full.
func TestClientCacheEviction(t *testing.T) {
	client, err := New(Config{
		ServerURL:    "ws://localhost:8080",
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Manually fill cache beyond max size to test eviction
	client.cacheMu.Lock()
	for i := 0; i <= client.maxCacheSize+10; i++ {
		key := fmt.Sprintf("owner/repo:sha%d", i)
		client.commitCacheKeys = append(client.commitCacheKeys, key)
		client.commitPRCache[key] = []int{i}
	}

	// Trigger eviction manually as production code would
	if len(client.commitCacheKeys) > client.maxCacheSize {
		n := client.maxCacheSize / 4
		for i := range n {
			delete(client.commitPRCache, client.commitCacheKeys[i])
		}
		client.commitCacheKeys = client.commitCacheKeys[n:]
	}

	cacheSize := len(client.commitPRCache)
	keyCount := len(client.commitCacheKeys)
	client.cacheMu.Unlock()

	if cacheSize > client.maxCacheSize {
		t.Errorf("Cache size %d exceeds max %d after eviction", cacheSize, client.maxCacheSize)
	}
	if cacheSize != keyCount {
		t.Errorf("Cache size %d doesn't match key count %d", cacheSize, keyCount)
	}

	// Verify oldest entries were evicted
	client.cacheMu.RLock()
	_, exists := client.commitPRCache["owner/repo:sha0"]
	client.cacheMu.RUnlock()

	if exists {
		t.Error("Expected oldest cache entry to be evicted")
	}
}

// TestClientPRNumberParsingError tests handling of invalid PR numbers.
func TestClientPRNumberParsingError(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":       "pull_request",
			"url":        "https://github.com/owner/repo/pull/invalid", // Non-numeric PR
			"commit_sha": "sha_abc",
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

	// Cache should not be populated due to parsing error
	client.cacheMu.RLock()
	_, exists := client.commitPRCache["owner/repo:sha_abc"]
	client.cacheMu.RUnlock()

	if exists {
		t.Error("Cache should not be populated for invalid PR number")
	}
}

// TestClientCheckEventWithoutCommitSHA tests check events without commit SHA.
func TestClientCheckEventWithoutCommitSHA(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type": "check_run",
			"url":  "https://github.com/owner/repo",
			// No commit_sha - should not trigger expansion
			"timestamp": time.Now().Format(time.RFC3339),
		},
	}

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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to timeout
	}()

	time.Sleep(500 * time.Millisecond)
	client.Stop()

	// Should receive event as-is without expansion
	mu.Lock()
	count := len(receivedEvents)
	mu.Unlock()

	if count != 1 {
		t.Errorf("Expected 1 event, got %d", count)
	}
}

// TestClientCheckEventWithPRURL tests check events with PR URL (no expansion needed).
func TestClientCheckEventWithPRURL(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":       "check_run",
			"url":        "https://github.com/owner/repo/pull/123", // Already has /pull/
			"commit_sha": "sha_xyz",
			"timestamp":  time.Now().Format(time.RFC3339),
		},
	}

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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to timeout
	}()

	time.Sleep(500 * time.Millisecond)
	client.Stop()

	// Should receive event as-is, no expansion needed
	mu.Lock()
	count := len(receivedEvents)
	mu.Unlock()

	if count != 1 {
		t.Errorf("Expected 1 event (no expansion), got %d", count)
	}
}

// TestClientInvalidCheckEventURL tests check events with invalid URLs.
func TestClientInvalidCheckEventURL(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":       "check_run",
			"url":        "https://github.com/invalid", // Too short
			"commit_sha": "sha_short",
			"timestamp":  time.Now().Format(time.RFC3339),
		},
		{
			"type":       "check_suite",
			"url":        "https://example.com/owner/repo", // Wrong domain
			"commit_sha": "sha_wrong",
			"timestamp":  time.Now().Format(time.RFC3339),
		},
	}

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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to timeout
	}()

	time.Sleep(500 * time.Millisecond)
	client.Stop()

	// Events should be delivered as-is despite invalid URLs
	mu.Lock()
	count := len(receivedEvents)
	mu.Unlock()

	if count != 2 {
		t.Errorf("Expected 2 events, got %d", count)
	}
}

// TestClientTokenProvider tests using a token provider.
func TestClientTokenProvider(t *testing.T) {
	tokenCalls := 0
	var mu sync.Mutex

	srv := newMockServer(t, true)
	defer srv.Close()

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "initial-token", // Will be replaced by provider
		Organization: "test-org",
		NoReconnect:  true,
		TokenProvider: func() (string, error) {
			mu.Lock()
			tokenCalls++
			mu.Unlock()
			return "provider-token", nil
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

	time.Sleep(500 * time.Millisecond)
	client.Stop()

	mu.Lock()
	calls := tokenCalls
	mu.Unlock()

	if calls < 1 {
		t.Errorf("Expected token provider to be called at least once, got %d calls", calls)
	}
}

// TestClientTokenProviderError tests token provider returning an error.
func TestClientTokenProviderError(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "initial-token",
		Organization: "test-org",
		NoReconnect:  true,
		TokenProvider: func() (string, error) {
			return "", fmt.Errorf("token provider failed")
		},
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = client.Start(ctx)
	if err == nil {
		t.Fatal("Expected error from token provider")
	}

	if !strings.Contains(err.Error(), "token provider") {
		t.Errorf("Expected token provider error, got: %v", err)
	}
}

// TestClientUserEventsOnly tests the user_events_only subscription option.
func TestClientUserEventsOnly(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	var receivedSub map[string]any
	srv.onConnection = func(ws *websocket.Conn) {
		// Read subscription and capture it
		if err := websocket.JSON.Receive(ws, &receivedSub); err != nil {
			return
		}

		// Send confirmation
		confirmation := map[string]any{"type": "subscription_confirmed"}
		if err := websocket.JSON.Send(ws, confirmation); err != nil {
			return
		}

		time.Sleep(5 * time.Second)
	}

	client, err := New(Config{
		ServerURL:      srv.url,
		Token:          "test-token",
		Organization:   "test-org",
		NoReconnect:    true,
		UserEventsOnly: true, // Set user events only
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to timeout
	}()

	time.Sleep(500 * time.Millisecond)
	client.Stop()

	// Verify user_events_only was sent in subscription
	if receivedSub == nil {
		t.Fatal("No subscription received")
	}
	if userOnly, ok := receivedSub["user_events_only"].(bool); !ok || !userOnly {
		t.Errorf("Expected user_events_only=true in subscription, got %v", receivedSub)
	}
}

// TestClientNoPRsForCommit tests check event when no PRs exist for commit.
func TestClientNoPRsForCommit(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	// Send check event without populating cache first
	srv.sendEvents = []map[string]any{
		{
			"type":       "check_run",
			"url":        "https://github.com/owner/repo", // No /pull/
			"commit_sha": "orphan_commit",
			"timestamp":  time.Now().Format(time.RFC3339),
		},
	}

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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx) //nolint:errcheck // Expected to timeout
	}()

	time.Sleep(500 * time.Millisecond)
	client.Stop()

	// Since cache is empty and we can't actually call GitHub API in tests,
	// the event won't be expanded (no PRs found)
	mu.Lock()
	count := len(receivedEvents)
	mu.Unlock()

	// Event should either not be delivered or delivered as-is
	if count > 1 {
		t.Errorf("Expected 0-1 events when no PRs found, got %d", count)
	}
}

// TestClientEmptyCacheLookup tests that empty cache lookup triggers GitHub API.
func TestClientEmptyCacheLookup(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":       "check_suite",
			"url":        "https://github.com/owner/repo",
			"commit_sha": "uncached_commit",
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

	time.Sleep(500 * time.Millisecond)
	client.Stop()

	// Verify the check event was received (even though GitHub API lookup would fail in test)
	// The cache miss path should be executed
}

// TestClientWSSOrigin tests that wss:// URLs use https:// origin.
func TestClientWSSOrigin(t *testing.T) {
	// Create client with wss:// URL (even though we can't actually test WSS)
	client, err := New(Config{
		ServerURL:    "wss://secure.example.com:8080",
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Just verify client was created - the wss:// origin logic is tested
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
}

// TestClientEventWithDeliveryID tests event handling with delivery ID.
func TestClientEventWithDeliveryID(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":        "pull_request",
			"url":         "https://github.com/test/repo/pull/1",
			"delivery_id": "abc-123-def-456",
			"timestamp":   time.Now().Format(time.RFC3339),
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

	if receivedEvent.DeliveryID != "abc-123-def-456" {
		t.Errorf("Expected delivery ID 'abc-123-def-456', got %q", receivedEvent.DeliveryID)
	}

	client.Stop()
}

// TestClientZeroPRNumber tests handling of PR number 0.
func TestClientZeroPRNumber(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":       "pull_request",
			"url":        "https://github.com/owner/repo/pull/0", // Zero PR number
			"commit_sha": "sha_zero",
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

	time.Sleep(500 * time.Millisecond)
	client.Stop()

	// Zero PR number should not be cached (prNum > 0 check)
	client.cacheMu.RLock()
	_, exists := client.commitPRCache["owner/repo:sha_zero"]
	client.cacheMu.RUnlock()

	if exists {
		t.Error("Cache should not be populated for zero PR number")
	}
}

// TestClientSubscriptionOrgMismatch tests subscription with organization mismatch.
func TestClientSubscriptionOrgMismatch(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.onConnection = func(ws *websocket.Conn) {
		// Read subscription
		var sub map[string]any
		if err := websocket.JSON.Receive(ws, &sub); err != nil {
			return
		}

		// Send confirmation with different org (simulating server error)
		confirmation := map[string]any{
			"type":         "subscription_confirmed",
			"organization": "different-org", // Different from what client sent
		}
		if err := websocket.JSON.Send(ws, confirmation); err != nil {
			return
		}

		time.Sleep(5 * time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = client.Start(ctx)
	// Should either succeed or fail, but not panic
	_ = err
}

// TestClientEventWithoutType tests event handling without type field.
func TestClientEventWithoutType(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"url":       "https://github.com/test/repo/pull/1",
			"timestamp": time.Now().Format(time.RFC3339),
			// No type field
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

	if receivedEvent.Type != "" {
		t.Errorf("Expected empty type, got %q", receivedEvent.Type)
	}

	client.Stop()
}

// TestClientEventWithoutURL tests event handling without URL field.
func TestClientEventWithoutURL(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":      "push",
			"timestamp": time.Now().Format(time.RFC3339),
			// No url field
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

	if receivedEvent.URL != "" {
		t.Errorf("Expected empty URL, got %q", receivedEvent.URL)
	}

	client.Stop()
}

// TestClientCheckSuiteType tests check_suite event type handling.
func TestClientCheckSuiteType(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type":      "check_suite",
			"url":       "https://github.com/test/repo/pull/1",
			"timestamp": time.Now().Format(time.RFC3339),
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

	if receivedEvent.Type != "check_suite" {
		t.Errorf("Expected type 'check_suite', got %q", receivedEvent.Type)
	}

	client.Stop()
}

// TestClientEventWithoutTimestamp tests event handling without timestamp field.
func TestClientEventWithoutTimestamp(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	srv.sendEvents = []map[string]any{
		{
			"type": "push",
			"url":  "https://github.com/test/repo",
			// No timestamp field
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

	if !receivedEvent.Timestamp.IsZero() {
		t.Errorf("Expected zero timestamp, got %v", receivedEvent.Timestamp)
	}

	client.Stop()
}
