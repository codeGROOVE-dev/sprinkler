package hub

import (
	"context"
	"testing"
	"time"
)

func TestHub(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hub := NewHub()
	go hub.Run(ctx)

	// Test registering clients - properly initialize using NewClient
	client1 := NewClient(
		"client1",
		Subscription{Organization: "myorg", MyEventsOnly: true, Username: "alice"},
		nil, // No websocket connection for unit test
		hub,
		[]string{"myorg"}, // User's organizations
	)

	client2 := NewClient(
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

	hub.Broadcast(event, payload)

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
