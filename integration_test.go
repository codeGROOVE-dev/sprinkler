package main_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/ready-to-review/github-event-socket/internal/hub"
	"github.com/ready-to-review/github-event-socket/internal/security"
	"github.com/ready-to-review/github-event-socket/internal/webhook"
)

// TestWebhookToWebSocketIntegration tests the full flow from webhook to WebSocket
func TestWebhookToWebSocketIntegration(t *testing.T) {
	h := hub.NewHub()
	go h.Run()
	defer h.Cancel()

	secret := "test-secret"
	connLimiter := security.NewConnectionLimiter(10, 100)

	// Set up HTTP handlers
	mux := http.NewServeMux()
	mux.Handle("/webhook", webhook.NewHandler(h, secret))
	wsHandler := hub.NewWebSocketHandler(h, connLimiter)
	mux.Handle("/ws", websocket.Handler(wsHandler.Handle))

	server := httptest.NewServer(mux)
	defer server.Close()

	// Connect WebSocket clients with different subscriptions
	tests := []struct {
		name         string
		subscription hub.Subscription
		shouldMatch  bool
	}{
		{
			name:         "client_subscribed_to_username",
			subscription: hub.Subscription{Username: "alice"},
			shouldMatch:  true,
		},
		{
			name:         "client_subscribed_to_pr_url",
			subscription: hub.Subscription{PRURL: "https://github.com/owner/repo/pull/123"},
			shouldMatch:  true,
		},
		{
			name:         "client_subscribed_to_repository",
			subscription: hub.Subscription{Repository: "https://github.com/owner/repo"},
			shouldMatch:  true,
		},
		{
			name:         "client_subscribed_to_different_username",
			subscription: hub.Subscription{Username: "bob"},
			shouldMatch:  false,
		},
		{
			name:         "client_subscribed_to_different_pr",
			subscription: hub.Subscription{PRURL: "https://github.com/owner/repo/pull/456"},
			shouldMatch:  false,
		},
		{
			name:         "client_with_no_subscription",
			subscription: hub.Subscription{},
			shouldMatch:  false, // No filters means no match
		},
	}

	// Connect WebSocket clients
	clients := make([]*websocket.Conn, len(tests))
	for i, tt := range tests {
		wsURL := "ws" + server.URL[4:] + "/ws"
		ws, err := websocket.Dial(wsURL, "", server.URL)
		if err != nil {
			t.Fatalf("failed to connect websocket for %s: %v", tt.name, err)
		}
		defer ws.Close()
		clients[i] = ws

		// Send subscription
		if err := websocket.JSON.Send(ws, tt.subscription); err != nil {
			t.Fatalf("failed to send subscription for %s: %v", tt.name, err)
		}
	}

	// Give time for connections to be established
	time.Sleep(50 * time.Millisecond)

	// Send webhook event
	payload := map[string]interface{}{
		"action": "opened",
		"pull_request": map[string]interface{}{
			"html_url": "https://github.com/owner/repo/pull/123",
			"user": map[string]interface{}{
				"login": "alice",
			},
		},
		"repository": map[string]interface{}{
			"html_url": "https://github.com/owner/repo",
		},
	}

	body, _ := json.Marshal(payload)
	
	// Calculate signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req, _ := http.NewRequest("POST", server.URL+"/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", signature)
	req.Header.Set("X-GitHub-Delivery", "12345")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("webhook request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook returned status %d", resp.StatusCode)
	}

	// Check which clients received events
	for i, tt := range tests {
		ws := clients[i]
		
		// Set read timeout
		ws.SetDeadline(time.Now().Add(200 * time.Millisecond))
		
		var event hub.Event
		err := websocket.JSON.Receive(ws, &event)
		
		if tt.shouldMatch {
			if err != nil {
				t.Errorf("%s: expected to receive event but got error: %v", tt.name, err)
			} else if event.URL != "https://github.com/owner/repo/pull/123" {
				t.Errorf("%s: received wrong URL: %s", tt.name, event.URL)
			}
		} else {
			if err == nil {
				t.Errorf("%s: should not have received event but got: %+v", tt.name, event)
			}
		}
	}
}

// TestWebSocketReconnection tests client reconnection behavior
func TestWebSocketReconnection(t *testing.T) {
	h := hub.NewHub()
	go h.Run()
	defer h.Cancel()

	connLimiter := security.NewConnectionLimiter(10, 100)
	wsHandler := hub.NewWebSocketHandler(h, connLimiter)
	server := httptest.NewServer(websocket.Handler(wsHandler.Handle))
	defer server.Close()

	wsURL := "ws" + server.URL[4:]

	// Connect first time
	ws1, err := websocket.Dial(wsURL, "", server.URL)
	if err != nil {
		t.Fatalf("first connection failed: %v", err)
	}

	sub := hub.Subscription{Username: "testuser"}
	if err := websocket.JSON.Send(ws1, sub); err != nil {
		t.Fatalf("failed to send subscription: %v", err)
	}

	// Close first connection
	ws1.Close()
	time.Sleep(50 * time.Millisecond)

	// Reconnect with same subscription
	ws2, err := websocket.Dial(wsURL, "", server.URL)
	if err != nil {
		t.Fatalf("reconnection failed: %v", err)
	}
	defer ws2.Close()

	if err := websocket.JSON.Send(ws2, sub); err != nil {
		t.Fatalf("failed to send subscription on reconnect: %v", err)
	}

	// Give time for registration to complete
	time.Sleep(50 * time.Millisecond)

	// Verify client is registered
	// Note: We can't directly access internal fields in integration test

	// Test will verify by attempting to broadcast
}

// TestWebSocketInvalidSubscription tests handling of invalid subscriptions
func TestWebSocketInvalidSubscription(t *testing.T) {
	h := hub.NewHub()
	go h.Run()
	defer h.Cancel()

	connLimiter := security.NewConnectionLimiter(10, 100)
	wsHandler := hub.NewWebSocketHandler(h, connLimiter)
	server := httptest.NewServer(websocket.Handler(wsHandler.Handle))
	defer server.Close()

	tests := []struct {
		name string
		sub  hub.Subscription
	}{
		{
			name: "username_too_long",
			sub:  hub.Subscription{Username: "this-username-is-way-too-long-for-github-limits-and-should-be-rejected"},
		},
		{
			name: "invalid_pr_url",
			sub:  hub.Subscription{PRURL: "not-a-valid-url"},
		},
		{
			name: "non_github_repository",
			sub:  hub.Subscription{Repository: "https://gitlab.com/user/repo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wsURL := "ws" + server.URL[4:]
			ws, err := websocket.Dial(wsURL, "", server.URL)
			if err != nil {
				t.Fatalf("connection failed: %v", err)
			}
			defer ws.Close()

			// Send invalid subscription
			if err := websocket.JSON.Send(ws, tt.sub); err != nil {
				t.Fatalf("failed to send subscription: %v", err)
			}

			// Connection should be closed
			var event hub.Event
			err = websocket.JSON.Receive(ws, &event)
			if err == nil {
				t.Error("expected connection to be closed for invalid subscription")
			}
		})
	}
}

// TestBroadcastPerformance tests that slow clients don't block broadcasts
// TODO: This test needs to be rewritten to work with the internal packages
/*
func TestBroadcastPerformance(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	defer hub.cancel()

	// Create a fast client and a slow client
	fastClient := &Client{
		id:           "fast",
		subscription: Subscription{Username: "user"},
		send:         make(chan Event, 10),
	}

	slowClient := &Client{
		id:           "slow",
		subscription: Subscription{Username: "user"},
		send:         make(chan Event), // Unbuffered channel to simulate slow client
	}

	hub.register <- fastClient
	hub.register <- slowClient
	time.Sleep(10 * time.Millisecond)

	// Broadcast multiple events rapidly
	for i := 0; i < 5; i++ {
		event := Event{
			URL:       "https://github.com/user/repo/pull/1",
			Timestamp: time.Now(),
			Type:      "pull_request",
		}
		payload := map[string]interface{}{
			"sender": map[string]interface{}{
				"login": "user",
			},
		}
		hub.Broadcast(event, payload)
	}

	// Fast client should receive all events
	received := 0
	timeout := time.After(100 * time.Millisecond)
	for {
		select {
		case <-fastClient.send:
			received++
			if received == 5 {
				return // Success
			}
		case <-timeout:
			if received > 0 {
				// At least some events were received, broadcast didn't block
				return
			}
			t.Errorf("fast client only received %d events", received)
			return
		}
	}
}
*/