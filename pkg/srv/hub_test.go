package srv

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestHub(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hub := NewHub(false)
	go hub.Run(ctx)

	// Test registering clients - properly initialize using NewClient
	client1 := NewClientForTest(
		ctx,
		"client1",
		Subscription{Organization: "myorg", UserEventsOnly: true, Username: "alice"},
		nil, // No websocket connection for unit test
		hub,
		[]string{"myorg"}, // User's organizations
	)

	client2 := NewClientForTest(
		ctx,
		"client2",
		Subscription{Organization: "myorg"},
		nil, // No websocket connection for unit test
		hub,
		[]string{"myorg"}, // User's organizations
	)

	hub.register <- client1
	hub.register <- client2

	// Give the hub time to process
	time.Sleep(10 * time.Millisecond)

	hub.mu.RLock()
	clientCount := len(hub.clients)
	hub.mu.RUnlock()

	if clientCount != 2 {
		t.Errorf("expected 2 clients, got %d", clientCount)
	}

	// Test broadcast
	event := Event{
		URL:       "https://github.com/myorg/repo/pull/1",
		Timestamp: time.Now(),
		Type:      "pull_request",
	}

	payload := map[string]any{
		"repository": map[string]any{
			"owner": map[string]any{
				"login": "myorg",
			},
		},
		"pull_request": map[string]any{
			"user": map[string]any{
				"login": "alice",
			},
			"html_url": "https://github.com/myorg/repo/pull/1",
		},
	}

	hub.Broadcast(ctx, event, payload)

	// Both clients should receive the event
	select {
	case e := <-client1.send:
		if e.URL != event.URL {
			t.Errorf("client1 received wrong event URL: %s", e.URL)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("client1 did not receive event")
	}

	select {
	case e := <-client2.send:
		if e.URL != event.URL {
			t.Errorf("client2 received wrong event URL: %s", e.URL)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("client2 did not receive event")
	}

	// Test unregister
	hub.unregister <- "client1"
	time.Sleep(10 * time.Millisecond)

	hub.mu.RLock()
	clientCount = len(hub.clients)
	hub.mu.RUnlock()

	if clientCount != 1 {
		t.Errorf("expected 1 client after unregister, got %d", clientCount)
	}
}

// TestHubUnregisterNonExistent tests unregistering a client that doesn't exist.
func TestHubUnregisterNonExistent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	// Try to unregister a client that was never registered
	hub.unregister <- "non-existent-client-id"

	// Give it time to process
	time.Sleep(100 * time.Millisecond)

	// Should not panic or cause issues
}

// TestHubBroadcastWithNoMatches tests broadcasting when no clients match.
func TestHubBroadcastWithNoMatches(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	// Create a mock client with a specific organization
	client := NewClientForTest(
		ctx,
		"test-client",
		Subscription{Organization: "org-a"},
		nil,
		hub,
		nil,
	)

	// Register the client
	hub.register <- client
	time.Sleep(50 * time.Millisecond)

	// Broadcast an event for a different org (should not match)
	event := Event{
		Type: "pull_request",
		URL:  "https://github.com/org-b/repo/pull/1",
	}
	payload := map[string]any{
		"repository": map[string]any{
			"owner": map[string]any{
				"login": "org-b",
			},
		},
	}

	hub.Broadcast(ctx, event, payload)

	// Wait for broadcast to complete
	time.Sleep(100 * time.Millisecond)

	// Verify no event was sent to client
	select {
	case <-client.send:
		t.Error("Client should not have received event for non-matching org")
	default:
		// Good, no event received
	}

	// Clean up
	client.Close()
}

// TestHubTrySendEventPanicRecovery tests panic recovery in trySendEvent.
func TestHubTrySendEventPanicRecovery(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	// Create a client
	client := NewClientForTest(
		ctx,
		"test-client",
		Subscription{Organization: "test-org"},
		nil,
		hub,
		nil,
	)

	// Register the client
	hub.register <- client
	time.Sleep(50 * time.Millisecond)

	// Close the client to make channels closed
	client.Close()
	time.Sleep(50 * time.Millisecond)

	// Try to send an event - should recover from panic if channel is closed
	event := Event{
		Type: "pull_request",
		URL:  "https://github.com/test-org/repo/pull/1",
	}
	payload := map[string]any{
		"repository": map[string]any{
			"owner": map[string]any{
				"login": "test-org",
			},
		},
	}

	// This should not panic
	hub.Broadcast(ctx, event, payload)

	// Wait for broadcast to complete
	time.Sleep(100 * time.Millisecond)
}

// TestHubBroadcastContextCancellation tests broadcast with cancelled context.
func TestHubBroadcastContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	hub := NewHub(false)
	go hub.Run(context.Background()) // Run with non-cancelled context
	defer hub.Stop()

	event := Event{
		Type: "pull_request",
		URL:  "https://github.com/test-org/repo/pull/1",
	}
	payload := map[string]any{
		"type": "pull_request",
	}

	// Should return quickly due to cancelled context
	hub.Broadcast(ctx, event, payload)
}

// TestHubStopTwice tests calling Stop() multiple times.
func TestHubStopTwice(t *testing.T) {
	hub := NewHub(false)
	go hub.Run(context.Background())

	// Stop once
	hub.Stop()

	// Wait for hub to stop
	hub.Wait()

	// Stop again - should not panic or block
	hub.Stop()
}

// TestHubBroadcastChannelFull tests broadcast when channel is at capacity.
func TestHubBroadcastChannelFull(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)

	// Do NOT start hub.Run() - this prevents the channel from being drained

	event := Event{
		Type: "pull_request",
		URL:  "https://github.com/test-org/repo/pull/1",
	}
	payload := map[string]any{
		"type": "pull_request",
	}

	// Fill the broadcast channel buffer (1000 capacity)
	// Since hub.Run() is not running, channel won't be drained
	for range 1001 {
		hub.Broadcast(ctx, event, payload)
	}

	// The 1001st broadcast should hit the default case and log a warning
	// Verify no panic occurred
}

// TestClientSendChannelFull tests sending to a client with a full send buffer.
func TestClientSendChannelFull(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	// Create a client but don't start its Run() goroutine
	// This prevents the send channel from being drained
	client := NewClientForTest(
		ctx,
		"test-client",
		Subscription{Organization: "test-org"},
		nil, // No websocket connection
		hub,
		[]string{"test-org"},
	)

	// Register the client
	hub.register <- client
	time.Sleep(50 * time.Millisecond)

	event := Event{
		Type: "pull_request",
		URL:  "https://github.com/test-org/repo/pull/1",
	}
	payload := map[string]any{
		"repository": map[string]any{
			"owner": map[string]any{
				"login": "test-org",
			},
		},
	}

	// Fill the client's send channel buffer (100 capacity) and then some
	// Since client.Run() is not running, channel won't be drained
	// Send 150 events to ensure we hit the full channel case
	for range 150 {
		hub.Broadcast(ctx, event, payload)
	}

	// Wait for all broadcasts to be processed
	time.Sleep(200 * time.Millisecond)

	// Verify client's send channel is full
	if len(client.send) != 100 {
		t.Errorf("Expected client send channel to be full (100), got %d", len(client.send))
	}
}

// TestNewClientWithManyOrgs tests NewClient with more than 1000 organizations.
// This tests the org limiting logic.
func TestNewClientWithManyOrgs(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)

	// Create more than 1000 unique orgs
	manyOrgs := make([]string, 1500)
	for i := range 1500 {
		manyOrgs[i] = fmt.Sprintf("org-%d", i)
	}

	client := NewClientForTest(
		ctx,
		"test-client-many-orgs",
		Subscription{Organization: "*"},
		nil,
		hub,
		manyOrgs,
	)

	// Verify client was created and orgs were limited to 1000
	if len(client.userOrgs) != 1000 {
		t.Errorf("Expected 1000 orgs, got %d", len(client.userOrgs))
	}
}

// TestHubPeriodicCheckWithShortInterval tests the periodic check logic.
// This uses a short ticker interval to test the periodic check path quickly.
func TestHubPeriodicCheckWithShortInterval(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)

	// Set a short periodic check interval for testing
	hub.periodicCheckInterval = 50 * time.Millisecond

	go hub.Run(ctx)
	defer hub.Stop()

	// Register a few clients
	client1 := NewClientForTest(ctx, "client1", Subscription{Organization: "org1", Username: "alice"}, nil, hub, []string{"org1"})
	client2 := NewClientForTest(ctx, "client2", Subscription{Organization: "org2", Username: "bob"}, nil, hub, []string{"org2"})

	hub.register <- client1
	hub.register <- client2
	time.Sleep(10 * time.Millisecond)

	// Wait for at least one periodic check to fire
	time.Sleep(100 * time.Millisecond)

	// Verify clients are still registered
	if hub.ClientCount() != 2 {
		t.Errorf("Expected 2 clients, got %d", hub.ClientCount())
	}
}

// TestClientRunContextCancellation tests client.Run() exits when context is cancelled.
func TestClientRunContextCancellation(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	client := NewClientForTest(ctx, "test-client", Subscription{Organization: "test-org"}, nil, hub, []string{"test-org"})

	// Create cancelable context for client.Run()
	runCtx, cancel := context.WithCancel(ctx)

	// Start client.Run()
	go client.Run(runCtx, 1*time.Hour, 100*time.Millisecond)

	// Give Run() time to start
	time.Sleep(10 * time.Millisecond)

	// Cancel the context - should trigger ctx.Done() path
	cancel()

	// Wait for Run() to exit
	time.Sleep(50 * time.Millisecond)

	// Verify client is closed
	if !client.IsClosed() {
		t.Error("Expected client to be closed after context cancellation")
	}
}
