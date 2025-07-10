package hub

import (
	"testing"
	"time"
)

func TestHub(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	// Test registering clients
	client1 := &Client{
		id:           "client1",
		subscription: Subscription{Username: "alice"},
		send:         make(chan Event, 10),
	}

	client2 := &Client{
		id:           "client2",
		subscription: Subscription{PRURL: "https://github.com/user/repo/pull/1"},
		send:         make(chan Event, 10),
	}

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
		URL:       "https://github.com/user/repo/pull/1",
		Timestamp: time.Now(),
		Type:      "pull_request",
	}

	payload := map[string]interface{}{
		"pull_request": map[string]interface{}{
			"user": map[string]interface{}{
				"login": "alice",
			},
			"html_url": "https://github.com/user/repo/pull/1",
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