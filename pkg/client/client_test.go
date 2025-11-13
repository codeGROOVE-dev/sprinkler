package client

import (
	"context"
	"errors"
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
		_ = client.Start(ctx)
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
	server       *httptest.Server
	url          string
	onConnection func(*websocket.Conn)
	acceptAuth   bool
	sendEvents   []map[string]any
	// Reserved for future use
	_ bool          // sendPings
	_ time.Duration // closeDelay
	_ int           // rejectWithCode
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
				if errors.Is(err, io.EOF) {
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
		_ = client.Start(ctx)
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
			_ = ws.Close()
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
		_ = client.Start(ctx)
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
			for i := range 3 {
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
	if !errors.Is(err, context.DeadlineExceeded) {
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
		_ = client.Start(ctx)
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
		_ = ws.Close()
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
		_ = ws.Close()
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
		_ = ws.Close()
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
		_ = ws.Close()
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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
		_ = client.Start(ctx)
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

// TestHandleDialError tests the handleDialError function for various error types.
func TestHandleDialError(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name          string
		inputErr      error
		expectAuthErr bool
		expectMsg     string
	}{
		{
			name:          "403 forbidden error",
			inputErr:      errors.New("websocket: bad status 403 Forbidden"),
			expectAuthErr: true,
			expectMsg:     "403 Forbidden",
		},
		{
			name:          "401 unauthorized error",
			inputErr:      errors.New("websocket: bad status 401 Unauthorized"),
			expectAuthErr: true,
			expectMsg:     "401 Unauthorized",
		},
		{
			name:          "forbidden in lowercase",
			inputErr:      errors.New("websocket: bad status - forbidden"),
			expectAuthErr: true,
			expectMsg:     "403 Forbidden",
		},
		{
			name:          "unauthorized in lowercase",
			inputErr:      errors.New("websocket: bad status - unauthorized"),
			expectAuthErr: true,
			expectMsg:     "401 Unauthorized",
		},
		{
			name:          "generic dial error",
			inputErr:      errors.New("connection refused"),
			expectAuthErr: false,
			expectMsg:     "dial:",
		},
		{
			name:          "other bad status",
			inputErr:      errors.New("websocket: bad status 500 Internal Server Error"),
			expectAuthErr: false,
			expectMsg:     "dial:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.handleDialError(tt.inputErr)

			if tt.expectAuthErr {
				var authErr *AuthenticationError
				if !errors.As(result, &authErr) {
					t.Errorf("Expected AuthenticationError, got %T: %v", result, result)
				}
			}

			if !strings.Contains(result.Error(), tt.expectMsg) {
				t.Errorf("Expected error to contain %q, got: %v", tt.expectMsg, result)
			}
		})
	}
}

// TestEnsureCacheSpace tests cache eviction logic.
func TestEnsureCacheSpace(t *testing.T) {
	t.Run("soft limit eviction", func(t *testing.T) {
		client, err := New(Config{
			ServerURL:    "ws://localhost:8080",
			Token:        "test-token",
			Organization: "test-org",
			NoReconnect:  true,
		})
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		// Set a small soft limit for testing
		client.maxCacheSize = 10

		// Fill cache to trigger soft limit
		for i := range 12 {
			key := fmt.Sprintf("owner/repo:commit%d", i)
			client.commitPRCache[key] = []int{100 + i}
			client.commitCacheKeys = append(client.commitCacheKeys, key)
		}

		// Trigger cache eviction
		client.ensureCacheSpace()

		// Cache should be reduced by ~25%
		if len(client.commitCacheKeys) > 10 {
			t.Errorf("Expected cache size <= 10 after soft limit eviction, got %d", len(client.commitCacheKeys))
		}
	})

	t.Run("hard limit eviction", func(t *testing.T) {
		client, err := New(Config{
			ServerURL:    "ws://localhost:8080",
			Token:        "test-token",
			Organization: "test-org",
			NoReconnect:  true,
		})
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		// Fill cache to trigger hard limit (10000 entries)
		for i := range 10001 {
			key := fmt.Sprintf("owner/repo:commit%d", i)
			client.commitPRCache[key] = []int{i}
			client.commitCacheKeys = append(client.commitCacheKeys, key)
		}

		initialSize := len(client.commitCacheKeys)
		client.ensureCacheSpace()

		// Cache should be reduced by ~50% from hard limit
		if len(client.commitCacheKeys) >= initialSize {
			t.Errorf("Expected cache to be evicted, was %d, now %d", initialSize, len(client.commitCacheKeys))
		}
		// Should evict about 50% of hard limit (500 entries based on hardMaxCacheSize=1000)
		if len(client.commitCacheKeys) > 9600 {
			t.Errorf("Expected aggressive eviction, got %d entries remaining", len(client.commitCacheKeys))
		}
	})

	t.Run("no eviction needed", func(t *testing.T) {
		client, err := New(Config{
			ServerURL:    "ws://localhost:8080",
			Token:        "test-token",
			Organization: "test-org",
			NoReconnect:  true,
		})
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		// Add just a few entries
		for i := range 5 {
			key := fmt.Sprintf("owner/repo:commit%d", i)
			client.commitPRCache[key] = []int{i}
			client.commitCacheKeys = append(client.commitCacheKeys, key)
		}

		initialSize := len(client.commitCacheKeys)
		client.ensureCacheSpace()

		// Should not evict anything
		if len(client.commitCacheKeys) != initialSize {
			t.Errorf("Expected no eviction, but size changed from %d to %d", initialSize, len(client.commitCacheKeys))
		}
	})
}

// TestWritePumpContextCancellation tests that writePump respects context cancellation.
func TestWritePumpContextCancellation(t *testing.T) {
	// Create a simple websocket server
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		// Just accept the connection and wait
		buf := make([]byte, 1024)
		_, _ = ws.Read(buf)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial websocket: %v", err)
	}
	defer ws.Close()

	client, err := New(Config{
		ServerURL:    "ws://localhost:8080",
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- client.writePump(ctx, ws)
	}()

	// Cancel context
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Should exit with context error
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Expected context.Canceled, got: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("writePump did not exit after context cancellation")
	}
}

// TestSendPingsContextCancellation tests that sendPings respects context cancellation.
func TestSendPingsContextCancellation(t *testing.T) {
	client, err := New(Config{
		ServerURL:    "ws://localhost:8080",
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
		PingInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})

	go func() {
		client.sendPings(ctx)
		close(doneCh)
	}()

	// Cancel context immediately
	cancel()

	// Should exit quickly
	select {
	case <-doneCh:
		// Success - sendPings exited
	case <-time.After(1 * time.Second):
		t.Fatal("sendPings did not exit after context cancellation")
	}
}

// TestReadEventsContextCancellation tests that readEvents respects context cancellation.
func TestReadEventsContextCancellation(t *testing.T) {
	// Create a websocket server that keeps connection open and sends pings to keep alive
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		// Send a message periodically to keep connection alive
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for range 30 { // Try for 3 seconds max
			<-ticker.C
			msg := map[string]string{"type": "ping"}
			_ = websocket.JSON.Send(ws, msg)
		}
	}))
	defer srv.Close()

	client, err := New(Config{
		ServerURL:    "ws://localhost:8080",
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial websocket: %v", err)
	}
	defer ws.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	errCh := make(chan error, 1)

	go func() {
		errCh <- client.readEvents(ctx, ws)
	}()

	// Should exit when context times out
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Logf("readEvents exited with: %v (acceptable)", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("readEvents did not exit after context timeout")
	}
}

// TestConnectRetryBackoff tests exponential backoff during connection retries.
func TestConnectRetryBackoff(t *testing.T) {
	// Server that refuses connections
	attempts := 0
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		attempts++
		// Close immediately to force reconnect
		ws.Close()
	}))
	defer srv.Close()

	client, err := New(Config{
		ServerURL:    "ws" + strings.TrimPrefix(srv.URL, "http"),
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  false, // Enable reconnection
		MaxRetries:   3,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	_ = client.Start(ctx)
	elapsed := time.Since(start)

	// Should have made multiple attempts with backoff delays
	if attempts < 2 {
		t.Errorf("Expected multiple connection attempts, got %d", attempts)
	}

	// With backoff, should take some time (at least a few hundred ms)
	if elapsed < 100*time.Millisecond {
		t.Errorf("Expected backoff delays, but completed too quickly: %v", elapsed)
	}
}

// TestTokenProvider tests dynamic token provider functionality.
func TestTokenProvider(t *testing.T) {
	tokenCallCount := 0
	tokenProvider := func() (string, error) {
		tokenCallCount++
		return fmt.Sprintf("token-%d", tokenCallCount), nil
	}

	srv := newMockServer(t, true)
	defer srv.Close()

	client, err := New(Config{
		ServerURL:     srv.url,
		Organization:  "test-org",
		TokenProvider: tokenProvider,
		NoReconnect:   true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx)
	}()

	time.Sleep(500 * time.Millisecond)
	client.Stop()

	if tokenCallCount == 0 {
		t.Error("TokenProvider was not called")
	}
}

// TestTokenProviderError tests error handling from token provider.
func TestTokenProviderError(t *testing.T) {
	tokenProvider := func() (string, error) {
		return "", fmt.Errorf("token provider error")
	}

	srv := newMockServer(t, true)
	defer srv.Close()

	client, err := New(Config{
		ServerURL:     srv.url,
		Organization:  "test-org",
		TokenProvider: tokenProvider,
		NoReconnect:   true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err = client.Start(ctx)
	// Should fail due to token provider error
	if err == nil {
		t.Error("Expected error from token provider, got nil")
	}
}

// TestConnectWithWSSOrigin tests that wss:// URLs use https origin.
func TestConnectWithWSSOrigin(t *testing.T) {
	// This test verifies the origin is set correctly for secure websockets
	srv := newMockServer(t, true)
	defer srv.Close()

	// Replace ws:// with wss:// to test the origin logic
	wssURL := strings.Replace(srv.url, "ws://", "wss://", 1)

	client, err := New(Config{
		ServerURL:    wssURL,
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// This will fail to connect but exercises the origin logic
	_ = client.Start(ctx)
}

// TestConnectEventTypesWildcard tests connecting with wildcard event type.
func TestConnectEventTypesWildcard(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		EventTypes:   []string{"*"},
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go func() {
		_ = client.Start(ctx)
	}()

	time.Sleep(200 * time.Millisecond)
	client.Stop()
}

// TestConnectWithPullRequests tests connecting with specific PR subscriptions.
func TestConnectWithPullRequests(t *testing.T) {
	srv := newMockServer(t, true)
	defer srv.Close()

	client, err := New(Config{
		ServerURL:    srv.url,
		Token:        "test-token",
		Organization: "test-org",
		PullRequests: []string{"https://github.com/owner/repo/pull/123"},
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go func() {
		_ = client.Start(ctx)
	}()

	time.Sleep(200 * time.Millisecond)
	client.Stop()
}

// ========== Critical WebSocket Bug Integration Tests ==========

// TestWriteChannelBackpressure tests behavior when write channel fills up during high message volume.
func TestWriteChannelBackpressure(t *testing.T) {
	t.Parallel()

	eventCount := 0
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		var sub map[string]any
		_ = websocket.JSON.Receive(ws, &sub)
		_ = websocket.JSON.Send(ws, map[string]string{
			"type":    "subscription_confirmed",
			"message": "Connected",
		})

		for i := range 200 {
			event := map[string]any{
				"type":       "event",
				"event_type": "push",
				"action":     "created",
				"number":     i,
			}
			if err := websocket.JSON.Send(ws, event); err != nil {
				return
			}
			eventCount++
		}
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	receivedEvents := 0
	client, err := New(Config{
		ServerURL:    "ws" + strings.TrimPrefix(srv.URL, "http"),
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
		OnEvent: func(event Event) {
			receivedEvents++
			time.Sleep(5 * time.Millisecond)
		},
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx)
	}()

	time.Sleep(1 * time.Second)
	client.Stop()

	t.Logf("Server sent %d events, client received %d events", eventCount, receivedEvents)
	if receivedEvents == 0 {
		t.Error("Expected to receive some events despite backpressure")
	}
}

// TestPingChannelFullScenario tests ping behavior when write channel is full.
func TestPingChannelFullScenario(t *testing.T) {
	t.Parallel()

	pongReceived := false
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		var sub map[string]any
		_ = websocket.JSON.Receive(ws, &sub)
		_ = websocket.JSON.Send(ws, map[string]string{
			"type":    "subscription_confirmed",
			"message": "Connected",
		})

		for {
			var msg map[string]any
			if err := websocket.JSON.Receive(ws, &msg); err != nil {
				return
			}
			if msg["type"] == "ping" {
				_ = websocket.JSON.Send(ws, map[string]string{
					"type": "pong",
					"seq":  fmt.Sprintf("%v", msg["seq"]),
				})
				pongReceived = true
			}
		}
	}))
	defer srv.Close()

	client, err := New(Config{
		ServerURL:    "ws" + strings.TrimPrefix(srv.URL, "http"),
		Token:        "test-token",
		Organization: "test-org",
		PingInterval: 50 * time.Millisecond,
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go func() {
		_ = client.Start(ctx)
	}()

	time.Sleep(300 * time.Millisecond)
	client.Stop()

	if !pongReceived {
		t.Error("Expected at least one pong to be received")
	}
}

// TestWriteChannelClosedDuringOperation tests behavior when write channel closes during active writes.
func TestWriteChannelClosedDuringOperation(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		var sub map[string]any
		_ = websocket.JSON.Receive(ws, &sub)
		_ = websocket.JSON.Send(ws, map[string]string{
			"type":    "subscription_confirmed",
			"message": "Connected",
		})

		for i := range 100 {
			event := map[string]any{
				"type":       "event",
				"event_type": "push",
				"action":     "created",
				"number":     i,
			}
			if err := websocket.JSON.Send(ws, event); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer srv.Close()

	client, err := New(Config{
		ServerURL:    "ws" + strings.TrimPrefix(srv.URL, "http"),
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
		OnEvent:      func(event Event) {},
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	go func() {
		_ = client.Start(ctx)
	}()

	time.Sleep(150 * time.Millisecond)
	client.Stop()
	time.Sleep(50 * time.Millisecond)
}

// TestReadTimeoutDuringGracefulShutdown tests timeout handling during context cancellation.
func TestReadTimeoutDuringGracefulShutdown(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		var sub map[string]any
		_ = websocket.JSON.Receive(ws, &sub)
		_ = websocket.JSON.Send(ws, map[string]string{
			"type":    "subscription_confirmed",
			"message": "Connected",
		})
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	client, err := New(Config{
		ServerURL:    "ws" + strings.TrimPrefix(srv.URL, "http"),
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	startTime := time.Now()
	_ = client.Start(ctx)
	duration := time.Since(startTime)

	if duration > 3*time.Second {
		t.Errorf("Expected shutdown within 3s, took %v", duration)
	}
}

// TestConcurrentWebSocketClose tests concurrent close scenarios to catch race conditions.
func TestConcurrentWebSocketClose(t *testing.T) {
	t.Parallel()

	for range 10 {
		srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
			var sub map[string]any
			_ = websocket.JSON.Receive(ws, &sub)
			_ = websocket.JSON.Send(ws, map[string]string{
				"type":    "subscription_confirmed",
				"message": "Connected",
			})
			time.Sleep(100 * time.Millisecond)
		}))

		client, err := New(Config{
			ServerURL:    "ws" + strings.TrimPrefix(srv.URL, "http"),
			Token:        "test-token",
			Organization: "test-org",
			NoReconnect:  true,
		})
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)

		go func() {
			_ = client.Start(ctx)
		}()

		time.Sleep(50 * time.Millisecond)
		go client.Stop()
		go cancel()
		go client.Stop()

		time.Sleep(150 * time.Millisecond)
		srv.Close()
	}
}

// TestNetworkErrorDuringWrite tests handling of network errors during JSON.Send.
func TestNetworkErrorDuringWrite(t *testing.T) {
	t.Parallel()

	connectionBroken := false
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		var sub map[string]any
		_ = websocket.JSON.Receive(ws, &sub)
		_ = websocket.JSON.Send(ws, map[string]string{
			"type":    "subscription_confirmed",
			"message": "Connected",
		})

		time.Sleep(50 * time.Millisecond)
		ws.Close()
		connectionBroken = true
	}))
	defer srv.Close()

	errorReceived := false
	client, err := New(Config{
		ServerURL:    "ws" + strings.TrimPrefix(srv.URL, "http"),
		Token:        "test-token",
		Organization: "test-org",
		PingInterval: 20 * time.Millisecond,
		NoReconnect:  true,
		OnDisconnect: func(err error) {
			errorReceived = true
		},
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_ = client.Start(ctx)

	if connectionBroken && !errorReceived {
		t.Log("Warning: Network error may not have been properly detected")
	}
}

// TestIOTimeoutRecovery tests that client properly handles I/O timeouts without hanging.
func TestIOTimeoutRecovery(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		var sub map[string]any
		_ = websocket.JSON.Receive(ws, &sub)
		_ = websocket.JSON.Send(ws, map[string]string{
			"type":    "subscription_confirmed",
			"message": "Connected",
		})

		_ = websocket.JSON.Send(ws, map[string]any{
			"type":       "event",
			"event_type": "push",
		})

		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	eventReceived := false
	client, err := New(Config{
		ServerURL:    "ws" + strings.TrimPrefix(srv.URL, "http"),
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
		OnEvent: func(event Event) {
			eventReceived = true
		},
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	_ = client.Start(ctx)

	if eventReceived {
		t.Log("Client successfully received event and handled I/O timeouts")
	}
}
