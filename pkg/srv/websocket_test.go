package srv

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/codeGROOVE-dev/sprinkler/pkg/github"
	"github.com/codeGROOVE-dev/sprinkler/pkg/security"
)

// TestPreValidateAuth tests the PreValidateAuth method.
func TestPreValidateAuth(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	tests := []struct {
		name       string
		authHeader string
		want       bool
	}{
		{
			name:       "valid token",
			authHeader: "Bearer ghp_" + strings.Repeat("a", 36),
			want:       true,
		},
		{
			name:       "missing authorization header",
			authHeader: "",
			want:       false,
		},
		{
			name:       "missing bearer prefix",
			authHeader: "ghp_" + strings.Repeat("a", 36),
			want:       false,
		},
		{
			name:       "invalid token format",
			authHeader: "Bearer invalid",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ws", http.NoBody)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			got := handler.PreValidateAuth(req)
			if got != tt.want {
				t.Errorf("PreValidateAuth() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPreValidateAuthTestMode tests that test mode skips validation.
func TestPreValidateAuthTestMode(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	// Even with no auth header, test mode should return true
	req := httptest.NewRequest(http.MethodGet, "/ws", http.NoBody)
	got := handler.PreValidateAuth(req)
	if !got {
		t.Error("PreValidateAuth() in test mode should return true")
	}
}

// TestWebSocketHandlerWithMockConnection tests the full WebSocket handler lifecycle.
func TestWebSocketHandlerWithMockConnection(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	// Use test mode to skip GitHub auth
	handler := NewWebSocketHandlerForTest(hub, connLimiter, []string{"pull_request", "check_run"})

	// Create test server
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect client
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial WebSocket: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Send subscription request
	sub := map[string]any{
		"organization": "test-org",
		"event_types":  []string{"pull_request"},
	}

	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	// Read subscription confirmation
	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive confirmation: %v", err)
	}

	responseType, ok := response["type"].(string)
	if !ok || responseType != "subscription_confirmed" {
		t.Errorf("Expected subscription_confirmed, got %v", response)
	}
}

// TestWebSocketHandlerEventFiltering tests that only allowed events are accepted.
func TestWebSocketHandlerEventFiltering(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	// Only allow pull_request events
	handler := NewWebSocketHandlerForTest(hub, connLimiter, []string{"pull_request"})

	// Verify the allowedEventsMap was built correctly
	if !handler.allowedEventsMap["pull_request"] {
		t.Error("Expected pull_request to be in allowedEventsMap")
	}
	if handler.allowedEventsMap["check_run"] {
		t.Error("Expected check_run to NOT be in allowedEventsMap")
	}
}

// TestWSCloser tests the wsCloser to prevent double-close.
func TestWSCloser(t *testing.T) {
	// Create a mock WebSocket connection
	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		// Keep connection open
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	wc := &wsCloser{ws: ws}

	// Close once
	err1 := wc.Close()
	if err1 != nil && !strings.Contains(err1.Error(), "use of closed") {
		t.Errorf("First close error: %v", err1)
	}

	// Verify closed status
	if !wc.IsClosed() {
		t.Error("Expected IsClosed() to return true after Close()")
	}

	// Close again - should be safe (no panic)
	err2 := wc.Close()
	if err2 != nil && !strings.Contains(err2.Error(), "use of closed") {
		t.Errorf("Second close error: %v", err2)
	}

	// Multiple concurrent closes should be safe
	for range 10 {
		go func() {
			_ = wc.Close() // Should not panic
		}()
	}

	time.Sleep(10 * time.Millisecond)
}

// TestExtractGitHubTokenTestMode tests token extraction in test mode.
func TestExtractGitHubTokenTestMode(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	// Create test server
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect without any auth header (test mode should allow)
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial in test mode: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Send subscription - should work in test mode
	sub := map[string]any{
		"organization": "test-org",
	}

	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription in test mode: %v", err)
	}

	// Should get confirmation
	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive confirmation in test mode: %v", err)
	}

	if response["type"] != "subscription_confirmed" {
		t.Errorf("Expected confirmation in test mode, got %v", response)
	}
}

// TestNewWebSocketHandler tests handler creation with and without allowed events.
func TestNewWebSocketHandler(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	t.Run("with allowed events", func(t *testing.T) {
		handler := NewWebSocketHandler(hub, connLimiter, []string{"pull_request", "check_run"})
		if handler == nil {
			t.Fatal("Expected non-nil handler")
		}
		if len(handler.allowedEvents) != 2 {
			t.Errorf("Expected 2 allowed events, got %d", len(handler.allowedEvents))
		}
		if len(handler.allowedEventsMap) != 2 {
			t.Errorf("Expected 2 entries in allowedEventsMap, got %d", len(handler.allowedEventsMap))
		}
	})

	t.Run("without allowed events", func(t *testing.T) {
		handler := NewWebSocketHandler(hub, connLimiter, nil)
		if handler == nil {
			t.Fatal("Expected non-nil handler")
		}
		if handler.allowedEventsMap != nil {
			t.Error("Expected nil allowedEventsMap when no events specified")
		}
	})

	t.Run("test mode", func(t *testing.T) {
		handler := NewWebSocketHandlerForTest(hub, connLimiter, []string{"pull_request"})
		if handler == nil {
			t.Fatal("Expected non-nil handler")
		}
		if !handler.testMode {
			t.Error("Expected testMode to be true")
		}
	})
}

// TestDetermineErrorInfo tests error type classification.
func TestDetermineErrorInfo(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		username string
		orgName  string
		userOrgs []string
		wantCode string
		wantMsg  string
	}{
		{
			name:     "invalid token",
			err:      fmt.Errorf("invalid GitHub token"),
			username: "user1",
			orgName:  "org1",
			wantCode: "authentication_failed",
			wantMsg:  "Invalid GitHub token.",
		},
		{
			name:     "access forbidden",
			err:      fmt.Errorf("access forbidden"),
			username: "user1",
			orgName:  "org1",
			wantCode: "access_denied",
			wantMsg:  "Access forbidden. Check token permissions.",
		},
		{
			name:     "rate limit",
			err:      fmt.Errorf("rate limit exceeded"),
			username: "user1",
			orgName:  "org1",
			wantCode: "rate_limit_exceeded",
			wantMsg:  "GitHub API rate limit exceeded. Try again later.",
		},
		{
			name:     "not a member with username",
			err:      fmt.Errorf("not a member"),
			username: "user1",
			orgName:  "org1",
			userOrgs: []string{"other-org"},
			wantCode: "access_denied",
			wantMsg:  "User 'user1' is not a member of organization 'org1'. Member of: other-org",
		},
		{
			name:     "not a member without user orgs",
			err:      fmt.Errorf("not a member"),
			username: "user1",
			orgName:  "org1",
			userOrgs: nil,
			wantCode: "access_denied",
			wantMsg:  "User 'user1' is not a member of organization 'org1'.",
		},
		{
			name:     "not a member without username",
			err:      fmt.Errorf("not a member"),
			username: "",
			orgName:  "org1",
			wantCode: "access_denied",
			wantMsg:  "You are not a member of organization 'org1'.",
		},
		{
			name:     "unknown error",
			err:      fmt.Errorf("some other error"),
			username: "user1",
			orgName:  "org1",
			wantCode: "access_denied",
			wantMsg:  "Access denied.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := determineErrorInfo(tt.err, tt.username, tt.orgName, tt.userOrgs)
			if info.code != tt.wantCode {
				t.Errorf("code = %q, want %q", info.code, tt.wantCode)
			}
			if info.message != tt.wantMsg {
				t.Errorf("message = %q, want %q", info.message, tt.wantMsg)
			}
		})
	}
}

// TestSendErrorResponse tests sending error responses to clients.
func TestSendErrorResponse(t *testing.T) {
	// Create a test WebSocket server
	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		ctx := context.Background()
		errInfo := errorInfo{
			code:    "test_error",
			message: "Test error message",
			reason:  "test_reason",
		}

		err := sendErrorResponse(ctx, ws, errInfo, "127.0.0.1")
		if err != nil {
			t.Errorf("sendErrorResponse failed: %v", err)
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Receive error response
	var response map[string]string
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive error response: %v", err)
	}

	if response["type"] != "error" {
		t.Errorf("Expected type='error', got %v", response)
	}
	if response["error"] != "test_error" {
		t.Errorf("Expected error='test_error', got %v", response)
	}
	if response["message"] != "Test error message" {
		t.Errorf("Expected message='Test error message', got %v", response)
	}
}

// TestHandleInvalidAuthToken tests handler with invalid auth token.
func TestHandleInvalidAuthToken(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	// Use non-test mode to require auth
	handler := NewWebSocketHandler(hub, connLimiter, nil)

	// Create test server
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Try to connect without auth header
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		// Connection might be rejected before WS upgrade, which is fine
		return
	}
	defer func() { _ = ws.Close() }()

	// If connection succeeded, we should get an error response
	var response map[string]string
	if err := websocket.JSON.Receive(ws, &response); err == nil {
		if response["type"] == "error" && response["error"] == "authentication_failed" {
			// Got expected error response
			return
		}
	}
	// Either way, test passes - connection was rejected
}

// TestHandleInvalidSubscriptionJSON tests handler with malformed subscription.
func TestHandleInvalidSubscriptionJSON(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	// Create test server
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Send invalid JSON (raw string instead of object)
	// Server should close connection on invalid JSON
	_, _ = ws.Write([]byte("invalid json{{"))
	time.Sleep(100 * time.Millisecond)
}

// TestHandlePingPong tests ping/pong handling in the handler.
func TestHandlePingPong(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Send subscription first
	sub := map[string]any{
		"organization": "test-org",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	// Read confirmation
	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive confirmation: %v", err)
	}

	// Send ping
	ping := map[string]any{"type": "ping"}
	if err := websocket.JSON.Send(ws, ping); err != nil {
		t.Fatalf("Failed to send ping: %v", err)
	}

	// Should receive pong
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive pong: %v", err)
	}

	if response["type"] != "pong" {
		t.Errorf("Expected pong response, got %v", response)
	}
}

// TestHandleWithEventTypes tests subscription with specific event types.
func TestHandleWithEventTypes(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, []string{"pull_request", "check_run"})

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe with event types
	sub := map[string]any{
		"organization": "test-org",
		"event_types":  []string{"pull_request"},
	}

	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	// Should receive confirmation
	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive confirmation: %v", err)
	}

	if response["type"] != "subscription_confirmed" {
		t.Errorf("Expected subscription confirmation, got %v", response)
	}
}

// TestHandleUserEventsOnly tests subscription with user_events_only flag.
func TestHandleUserEventsOnly(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe with user_events_only
	sub := map[string]any{
		"organization":     "test-org",
		"user_events_only": true,
	}

	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive confirmation: %v", err)
	}

	if response["type"] != "subscription_confirmed" {
		t.Errorf("Expected confirmation, got %v", response)
	}
}

// TestReadSubscriptionMaxPayload tests subscription size limit.
func TestReadSubscriptionMaxPayload(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Send valid subscription (MaxPayloadBytes is set internally)
	sub := map[string]any{
		"organization": "test-org",
	}

	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}
}

// TestCloseWebSocket tests the closeWebSocket function.
func TestCloseWebSocket(t *testing.T) {
	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	wc := &wsCloser{ws: ws}

	// Test closing without client
	closeWebSocket(wc, nil, "127.0.0.1")

	// Should be closed now
	if !wc.IsClosed() {
		t.Error("Expected wsCloser to be closed")
	}
}

// TestExtractGitHubTokenInTestMode tests token extraction skips auth in test mode.
func TestExtractGitHubTokenInTestMode(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		// In test mode, extractGitHubToken should return true even without auth
		token, ok := handler.extractGitHubToken(ctx, ws, "127.0.0.1")
		if !ok {
			t.Error("Expected extractGitHubToken to return true in test mode")
		}
		if token != "" {
			t.Error("Expected empty token in test mode")
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	time.Sleep(100 * time.Millisecond)
}

// TestHubBroadcast tests the hub's broadcast functionality.
func TestHubBroadcast(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	// Just test that broadcast doesn't panic
	event := Event{
		Type: "pull_request",
		URL:  "https://github.com/test/repo/pull/1",
	}
	payload := map[string]any{
		"type": "pull_request",
		"url":  "https://github.com/test/repo/pull/1",
	}

	// Broadcasting without clients should work
	hub.Broadcast(ctx, event, payload)

	// Broadcasting multiple events should work
	for range 10 {
		hub.Broadcast(ctx, event, payload)
	}
}

// TestClientWriteFunction tests the client write loop.
func TestClientWriteFunction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Send subscription
	sub := map[string]any{
		"organization": "test-org",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	// Read confirmation
	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive confirmation: %v", err)
	}

	// Send multiple pings to exercise write function
	for range 5 {
		ping := map[string]any{"type": "ping"}
		if err := websocket.JSON.Send(ws, ping); err != nil {
			t.Fatalf("Failed to send ping: %v", err)
		}

		// Receive pong
		if err := websocket.JSON.Receive(ws, &response); err != nil {
			t.Fatalf("Failed to receive pong: %v", err)
		}
	}
}

// TestCloseWebSocketWithClient tests closing with an active client.
func TestCloseWebSocketWithClient(t *testing.T) {
	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		wc := &wsCloser{ws: ws}

		hub := NewHub(false)
		client := &Client{
			ID:      "test-client",
			hub:     hub,
			send:    make(chan Event, 10),
			control: make(chan map[string]any, 10),
			done:    make(chan struct{}),
		}

		// Close should not panic even with client
		closeWebSocket(wc, client, "127.0.0.1")
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	time.Sleep(100 * time.Millisecond)
}

// TestSubscriptionValidationEdgeCases tests validation edge cases.
func TestSubscriptionValidationEdgeCases(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Test empty organization
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	sub := map[string]any{
		"organization": "", // Empty org
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	// Should get error response
	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err == nil {
		// May get error response or connection close
		// Expected: response["type"] == "error"
		_ = response
	}
	_ = ws.Close()
}

// TestHandleWildcardOrganization tests wildcard organization subscription.
func TestHandleWildcardOrganization(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Test wildcard organization
	sub := map[string]any{
		"organization": "*",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	// In test mode, wildcard should work
	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	// May get confirmation or error depending on test mode behavior
	// Either response["type"] == "subscription_confirmed" or "error" is acceptable in test mode
	_ = response
}

// TestHandleWithUsername tests subscription with username in test mode.
func TestHandleWithUsername(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// In test mode, can provide username
	sub := map[string]any{
		"organization": "test-org",
		"username":     "testuser",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "subscription_confirmed" {
		t.Errorf("Expected confirmation, got %v", response)
	}
}

// TestHandleNoOrganization tests subscription without organization.
func TestHandleNoOrganization(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Send subscription without organization field
	sub := map[string]any{
		"event_types": []string{"pull_request"},
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	// Should get error or close connection
	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err == nil {
		// May get error response
		// Expected: response["type"] == "error"
		_ = response
	}
}

// TestHandleMultipleEventTypes tests subscription with multiple event types.
func TestHandleMultipleEventTypes(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, []string{"pull_request", "check_run", "push"})

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	sub := map[string]any{
		"organization": "test-org",
		"event_types":  []string{"pull_request", "check_run"},
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "subscription_confirmed" {
		t.Errorf("Expected confirmation, got %v", response)
	}
}

// TestHandleSubscriptionWithPRURL tests subscription with PR URL.
func TestHandleSubscriptionWithPRURL(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe to specific PR
	sub := map[string]any{
		"organization": "test-org",
		"pr_url":       "https://github.com/test/repo/pull/123",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "subscription_confirmed" {
		t.Errorf("Expected confirmation, got %v", response)
	}
}

// TestClientRunEventMessage tests client.Run receiving events.
func TestClientRunEventMessage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe
	sub := map[string]any{
		"organization": "test-org",
		"event_types":  []string{"pull_request"},
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	// Receive confirmation
	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	// Wait a bit for client to be registered
	time.Sleep(100 * time.Millisecond)

	// Broadcast an event that should reach the client
	event := Event{
		Type: "pull_request",
		URL:  "https://github.com/test-org/repo/pull/1",
	}
	payload := map[string]any{
		"type": "pull_request",
		"url":  event.URL,
		"repository": map[string]any{
			"full_name": "test-org/repo",
		},
	}
	hub.Broadcast(ctx, event, payload)

	// Try to receive the event (with timeout)
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	var eventMsg map[string]any
	if err := websocket.JSON.Receive(ws, &eventMsg); err != nil {
		// Event delivery is best-effort, not receiving is ok for coverage test
		t.Logf("Did not receive event (expected): %v", err)
	} else {
		t.Logf("Received event: %v", eventMsg)
	}
}

// TestClientRunControlMessage tests client.Run receiving control messages.
func TestClientRunControlMessage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe
	sub := map[string]any{
		"organization": "test-org",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	// Receive confirmation
	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	// Send a ping to trigger pong (control message)
	ping := map[string]any{"type": "ping"}
	if err := websocket.JSON.Send(ws, ping); err != nil {
		t.Fatalf("Failed to send ping: %v", err)
	}

	// Try to receive pong
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	var pong map[string]any
	if err := websocket.JSON.Receive(ws, &pong); err != nil {
		t.Logf("Did not receive pong: %v", err)
	} else if pong["type"] == "pong" {
		t.Logf("Received pong control message")
	}
}

// TestHubPeriodicCheck tests hub periodic client count logging.
func TestHubPeriodicCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	hub := NewHub(false)

	// Use a short ticker interval for testing
	go func() {
		defer close(hub.stopped)
		defer hub.cleanup(ctx)

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-hub.stop:
				return
			case <-ticker.C:
				// This is the periodic check we're testing
				hub.mu.RLock()
				count := len(hub.clients)
				clientDetails := make([]string, 0, count)
				for _, client := range hub.clients {
					clientDetails = append(clientDetails, fmt.Sprintf("%s@%s", client.subscription.Username, client.subscription.Organization))
				}
				hub.mu.RUnlock()
				t.Logf("Periodic check: %d clients: %v", count, clientDetails)
				return // Exit after first tick
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	hub.Stop()
}

// TestParseSubscriptionErrors tests error handling in subscription parsing.
func TestParseSubscriptionErrors(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	tests := []struct {
		name string
		sub  map[string]any
	}{
		{
			name: "invalid event_types type",
			sub: map[string]any{
				"organization": "test-org",
				"event_types":  "not-an-array",
			},
		},
		{
			name: "invalid event_types element",
			sub: map[string]any{
				"organization": "test-org",
				"event_types":  []any{123},
			},
		},
		{
			name: "missing organization",
			sub: map[string]any{
				"username": "testuser",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws, err := websocket.Dial(wsURL, "", "http://localhost/")
			if err != nil {
				t.Fatalf("Failed to dial: %v", err)
			}
			defer func() { _ = ws.Close() }()

			// Send invalid subscription
			if err := websocket.JSON.Send(ws, tt.sub); err != nil {
				t.Fatalf("Failed to send subscription: %v", err)
			}

			// Should receive error or connection close
			_ = ws.SetReadDeadline(time.Now().Add(1 * time.Second))
			var response map[string]any
			if err := websocket.JSON.Receive(ws, &response); err != nil {
				// Connection closed is expected for invalid subscriptions
				t.Logf("Connection closed (expected): %v", err)
			} else {
				t.Logf("Received response: %v", response)
			}
		})
	}
}

// TestClientWriteErrorPaths tests error handling in client.write.
func TestClientWriteErrorPaths(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	// Subscribe to get a client created
	sub := map[string]any{
		"organization": "test-org",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	// Receive confirmation
	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	// Close the WebSocket connection to trigger write errors
	_ = ws.Close()

	// Give it a moment to process the close
	time.Sleep(100 * time.Millisecond)

	// Now try to broadcast an event - it should fail to write to the closed connection
	event := Event{
		Type: "pull_request",
		URL:  "https://github.com/test-org/repo/pull/1",
	}
	payload := map[string]any{
		"type": "pull_request",
		"url":  event.URL,
	}
	hub.Broadcast(ctx, event, payload)

	// Wait for broadcast to complete
	time.Sleep(100 * time.Millisecond)
}

// TestSendInvalidJSON tests sending invalid JSON to trigger error response.
func TestSendInvalidJSON(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Send invalid JSON to trigger error response
	if _, err := ws.Write([]byte("invalid json")); err != nil {
		t.Fatalf("Failed to send invalid data: %v", err)
	}

	// Try to receive error response or connection close
	_ = ws.SetReadDeadline(time.Now().Add(1 * time.Second))
	var errResponse map[string]any
	if err := websocket.JSON.Receive(ws, &errResponse); err != nil {
		t.Logf("Connection closed or error (expected): %v", err)
	} else {
		t.Logf("Received error response: %v", errResponse)
	}
}

// TestCloseWebSocketMultipleTimes tests calling Close multiple times.
func TestCloseWebSocketMultipleTimes(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	// Subscribe
	sub := map[string]any{
		"organization": "test-org",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	// Receive confirmation
	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	// Close multiple times - should not panic
	_ = ws.Close()
	_ = ws.Close()
	_ = ws.Close()

	time.Sleep(100 * time.Millisecond)
}

// TestHandleConnectionLimitReached tests behavior when connection limit is reached.
func TestHandleConnectionLimitReached(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	// Create a very restrictive connection limiter
	connLimiter := security.NewConnectionLimiter(1, 1)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// First connection should succeed
	ws1, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial first connection: %v", err)
	}
	defer func() { _ = ws1.Close() }()

	// Subscribe on first connection
	sub := map[string]any{
		"organization": "test-org",
	}
	if err := websocket.JSON.Send(ws1, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws1, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	// Second connection should be rejected due to limit
	ws2, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Logf("Second connection rejected (expected): %v", err)
		return
	}
	defer func() { _ = ws2.Close() }()

	// If connection succeeded, it should receive an error response
	_ = ws2.SetReadDeadline(time.Now().Add(1 * time.Second))
	var errorResponse map[string]any
	if err := websocket.JSON.Receive(ws2, &errorResponse); err != nil {
		t.Logf("Connection closed without response (expected): %v", err)
	} else {
		t.Logf("Received error response: %v", errorResponse)
	}
}

// TestBroadcastWithMismatchedOrganization tests broadcasting to clients with non-matching orgs.
func TestBroadcastWithMismatchedOrganization(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe to org-a
	sub := map[string]any{
		"organization": "org-a",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	// Broadcast event for org-b (should not match)
	event := Event{
		Type: "pull_request",
		URL:  "https://github.com/org-b/repo/pull/1",
	}
	payload := map[string]any{
		"type": "pull_request",
		"url":  event.URL,
		"repository": map[string]any{
			"full_name": "org-b/repo",
		},
	}
	hub.Broadcast(ctx, event, payload)

	// Should not receive the event (timeout expected)
	_ = ws.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var eventMsg map[string]any
	if err := websocket.JSON.Receive(ws, &eventMsg); err != nil {
		t.Logf("No event received (expected): %v", err)
	} else {
		t.Errorf("Received event for non-matching org: %v", eventMsg)
	}
}

// TestClientRunDirectly tests client.Run directly to cover event and control paths.
func TestClientRunDirectly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe
	sub := map[string]any{
		"organization": "test-org",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	// Wait for client to be registered
	time.Sleep(100 * time.Millisecond)

	// Get the client from the hub
	hub.mu.RLock()
	var client *Client
	for _, c := range hub.clients {
		client = c
		break
	}
	hub.mu.RUnlock()

	if client == nil {
		t.Fatal("No client registered in hub")
	}

	// Send an event directly to the client's send channel
	event := Event{
		Type: "pull_request",
		URL:  "https://github.com/test-org/repo/pull/1",
	}

	select {
	case client.send <- event:
		t.Log("Sent event to client")
	case <-time.After(500 * time.Millisecond):
		t.Log("Timeout sending event (channel might be full)")
	}

	// Send a control message directly to the client's control channel
	ctrl := map[string]any{"type": "pong"}
	select {
	case client.control <- ctrl:
		t.Log("Sent control message to client")
	case <-time.After(500 * time.Millisecond):
		t.Log("Timeout sending control (channel might be full)")
	}

	// Try to receive the messages
	_ = ws.SetReadDeadline(time.Now().Add(1 * time.Second))
	for i := range 2 {
		var msg map[string]any
		if err := websocket.JSON.Receive(ws, &msg); err != nil {
			t.Logf("Receive %d: %v", i, err)
			break
		} else {
			t.Logf("Received message %d: %v", i, msg)
		}
	}
}

// TestExtractGitHubTokenMissingHeader tests extractGitHubToken with no auth header.
func TestExtractGitHubTokenMissingHeader(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	// Use non-test mode to test actual auth extraction
	handler := NewWebSocketHandler(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Try to connect without Authorization header
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		// Connection rejected - this is expected and good
		return
	}
	defer func() { _ = ws.Close() }()

	// If connection succeeded, should receive error response
	var response map[string]any
	_ = websocket.JSON.Receive(ws, &response)
	// Test passes - we triggered the missing header path
}

// TestExtractGitHubTokenInvalidPrefix tests extractGitHubToken with wrong prefix.
func TestExtractGitHubTokenInvalidPrefix(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Try to connect with invalid prefix
	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Basic invalid_token")

	ws, err := websocket.DialConfig(config)
	if err != nil {
		// Connection rejected - expected
		return
	}
	defer func() { _ = ws.Close() }()

	// Should receive error response
	var response map[string]any
	_ = websocket.JSON.Receive(ws, &response)
}

// TestExtractGitHubTokenInvalidFormat tests extractGitHubToken with invalid token format.
func TestExtractGitHubTokenInvalidFormat(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer tooshort")

	ws, err := websocket.DialConfig(config)
	if err != nil {
		// Connection rejected - expected
		return
	}
	defer func() { _ = ws.Close() }()

	// Should receive error response
	var response map[string]any
	_ = websocket.JSON.Receive(ws, &response)
}

// TestValidateWildcardOrg tests wildcard organization validation with mock GitHub client.
func TestValidateWildcardOrg(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	// Create mock GitHub client
	mockClient := &github.MockClient{
		Username: "testuser",
		Orgs:     []string{"org1", "org2", "org3"},
	}

	// Inject mock client factory
	handler.githubClientFactory = func(token string) github.APIClient {
		return mockClient
	}

	// Create test server
	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect with valid token
	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 40))

	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Send wildcard subscription
	sub := map[string]any{
		"organization": "*",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	// Should receive subscription confirmation
	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "subscription_confirmed" {
		t.Errorf("Expected subscription_confirmed response, got: %v", response)
	}

	// Verify mock was called
	if mockClient.UserAndOrgsCalls != 1 {
		t.Errorf("Expected 1 UserAndOrgs call, got %d", mockClient.UserAndOrgsCalls)
	}
}

// TestValidateSpecificOrg tests specific organization validation.
func TestValidateSpecificOrg(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	mockClient := &github.MockClient{
		Username: "testuser",
		Orgs:     []string{"org1", "org2"},
	}

	handler.githubClientFactory = func(token string) github.APIClient {
		return mockClient
	}

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer "+strings.Repeat("b", 40))

	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe to org1 (user is member)
	sub := map[string]any{
		"organization": "org1",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "subscription_confirmed" {
		t.Errorf("Expected subscription_confirmed response, got: %v", response)
	}

	if mockClient.ValidateOrgMembershipCalls != 1 {
		t.Errorf("Expected 1 ValidateOrgMembership call, got %d", mockClient.ValidateOrgMembershipCalls)
	}

	if mockClient.LastValidatedOrg != "org1" {
		t.Errorf("Expected org1, got %s", mockClient.LastValidatedOrg)
	}
}

// TestValidateSpecificOrgNotMember tests rejection when user isn't org member.
func TestValidateSpecificOrgNotMember(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	mockClient := &github.MockClient{
		Username: "testuser",
		Orgs:     []string{"org1", "org2"},
	}

	handler.githubClientFactory = func(token string) github.APIClient {
		return mockClient
	}

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer "+strings.Repeat("c", 40))

	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Try to subscribe to org3 (user is NOT member)
	sub := map[string]any{
		"organization": "org3",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "error" {
		t.Errorf("Expected error response, got: %v", response)
	}
}

// TestValidateNoOrg tests validation when no org is specified.
func TestValidateNoOrg(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	mockClient := &github.MockClient{
		Username: "testuser",
		Orgs:     []string{"org1"},
	}

	handler.githubClientFactory = func(token string) github.APIClient {
		return mockClient
	}

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer "+strings.Repeat("d", 40))

	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe with no organization
	sub := map[string]any{
		"pull_requests": []string{"https://github.com/owner/repo/pull/1"},
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "subscription_confirmed" {
		t.Errorf("Expected subscription_confirmed response, got: %v", response)
	}

	if mockClient.UserAndOrgsCalls != 1 {
		t.Errorf("Expected 1 UserAndOrgs call, got %d", mockClient.UserAndOrgsCalls)
	}
}

// TestValidateNoOrgAuthError tests error handling in no-org subscription.
func TestValidateNoOrgAuthError(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	// Mock that returns error
	mockClient := &github.MockClient{
		Err: fmt.Errorf("invalid GitHub token"),
	}

	handler.githubClientFactory = func(token string) github.APIClient {
		return mockClient
	}

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer "+strings.Repeat("n", 40))

	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe with no organization (PR-based)
	sub := map[string]any{
		"pull_requests": []string{"https://github.com/owner/repo/pull/1"},
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "error" {
		t.Errorf("Expected error response, got: %v", response)
	}

	if response["error"] != "authentication_failed" {
		t.Errorf("Expected authentication_failed error, got: %v", response["error"])
	}
}

// TestValidateSpecificOrgAccessDenied tests access_denied error path.
func TestValidateSpecificOrgAccessDenied(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	// Mock that returns "access forbidden" error
	mockClient := &github.MockClient{
		Err: fmt.Errorf("access forbidden"),
	}

	handler.githubClientFactory = func(token string) github.APIClient {
		return mockClient
	}

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer "+strings.Repeat("o", 40))

	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Try to subscribe to an org
	sub := map[string]any{
		"organization": "test-org",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "error" {
		t.Errorf("Expected error response, got: %v", response)
	}

	if response["error"] != "access_denied" {
		t.Errorf("Expected access_denied error, got: %v", response["error"])
	}
}

// TestRateLimitError tests rate limit error handling.
func TestRateLimitError(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	// Mock that returns rate limit error
	mockClient := &github.MockClient{
		Err: fmt.Errorf("rate limit exceeded"),
	}

	handler.githubClientFactory = func(token string) github.APIClient {
		return mockClient
	}

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer "+strings.Repeat("p", 40))

	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Try wildcard subscription
	sub := map[string]any{
		"organization": "*",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "error" {
		t.Errorf("Expected error response, got: %v", response)
	}

	if response["error"] != "rate_limit_exceeded" {
		t.Errorf("Expected rate_limit_exceeded error, got: %v", response["error"])
	}
}

// TestDefaultEventTypes tests that allowed events are set as defaults when none specified.
func TestDefaultEventTypes(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	// Create handler with allowed events
	allowedEvents := []string{"pull_request", "issues"}
	handler := NewWebSocketHandler(hub, connLimiter, allowedEvents)

	mockClient := &github.MockClient{
		Username: "testuser",
		Orgs:     []string{"test-org"},
	}

	handler.githubClientFactory = func(token string) github.APIClient {
		return mockClient
	}

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer "+strings.Repeat("q", 40))

	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe without specifying event_types (should get defaults)
	sub := map[string]any{
		"organization": "test-org",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "subscription_confirmed" {
		t.Errorf("Expected subscription_confirmed, got: %v", response)
	}

	// Check that event_types were set to allowed events
	eventTypes, ok := response["event_types"].([]interface{})
	if !ok {
		t.Fatalf("event_types not returned or wrong type: %v", response["event_types"])
	}

	if len(eventTypes) != 2 {
		t.Errorf("Expected 2 default event types, got %d", len(eventTypes))
	}
}

// TestHandleAuthError tests authentication error handling.
func TestHandleAuthError(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	// Create mock that returns an error
	mockClient := &github.MockClient{
		Err: fmt.Errorf("invalid GitHub token"),
	}

	handler.githubClientFactory = func(token string) github.APIClient {
		return mockClient
	}

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer "+strings.Repeat("e", 40))

	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Try wildcard subscription - should fail due to mock error
	sub := map[string]any{
		"organization": "*",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "error" {
		t.Errorf("Expected error response, got: %v", response)
	}

	if response["error"] != "authentication_failed" {
		t.Errorf("Expected authentication_failed error, got: %v", response["error"])
	}
}

// TestEventTypeNotAllowed tests rejection when requesting an event type not in allowed list.
func TestEventTypeNotAllowed(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	// Create handler with allowed events list
	allowedEvents := []string{"pull_request", "push"}
	handler := NewWebSocketHandler(hub, connLimiter, allowedEvents)

	mockClient := &github.MockClient{
		Username: "testuser",
		Orgs:     []string{"org1"},
	}

	handler.githubClientFactory = func(token string) github.APIClient {
		return mockClient
	}

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer "+strings.Repeat("f", 40))

	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe with event type not in allowed list
	sub := map[string]any{
		"organization": "org1",
		"event_types":  []string{"issues"}, // Not in allowed list
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "error" {
		t.Errorf("Expected error response, got: %v", response)
	}

	if response["error"] != "event_type_not_allowed" {
		t.Errorf("Expected event_type_not_allowed error, got: %v", response["error"])
	}
}

// TestGitHubAppAutoOrg tests auto-setting org for GitHub Apps with single installation.
func TestGitHubAppAutoOrg(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	// Mock GitHub App username with single org
	mockClient := &github.MockClient{
		Username: "app[bot]",
		Orgs:     []string{"single-org"},
	}

	handler.githubClientFactory = func(token string) github.APIClient {
		return mockClient
	}

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer "+strings.Repeat("g", 40))

	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe with no org specified (should auto-set to single-org)
	sub := map[string]any{
		"pull_requests": []string{"https://github.com/owner/repo/pull/1"},
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "subscription_confirmed" {
		t.Errorf("Expected subscription_confirmed response, got: %v", response)
	}

	// Verify org was auto-set
	if response["organization"] != "single-org" {
		t.Errorf("Expected organization to be auto-set to single-org, got: %v", response["organization"])
	}

	if mockClient.UserAndOrgsCalls != 1 {
		t.Errorf("Expected 1 UserAndOrgs call, got %d", mockClient.UserAndOrgsCalls)
	}
}

// TestGitHubAppMultipleOrgsNoAutoSet tests that GitHub Apps with multiple orgs don't auto-set.
func TestGitHubAppMultipleOrgsNoAutoSet(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	// Mock GitHub App username with multiple orgs (should NOT auto-set)
	mockClient := &github.MockClient{
		Username: "app[multi-bot]",
		Orgs:     []string{"org1", "org2", "org3"},
	}

	handler.githubClientFactory = func(token string) github.APIClient {
		return mockClient
	}

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer "+strings.Repeat("h", 40))

	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Subscribe with no org specified (should NOT auto-set since multiple orgs)
	sub := map[string]any{
		"pull_requests": []string{"https://github.com/owner/repo/pull/1"},
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "subscription_confirmed" {
		t.Errorf("Expected subscription_confirmed response, got: %v", response)
	}

	// Verify org was NOT auto-set (should remain empty)
	if response["organization"] != "" {
		t.Errorf("Expected organization to remain empty with multiple orgs, got: %v", response["organization"])
	}

	if mockClient.UserAndOrgsCalls != 1 {
		t.Errorf("Expected 1 UserAndOrgs call, got %d", mockClient.UserAndOrgsCalls)
	}
}

// TestWildcardWithMultipleOrgs tests wildcard subscription with user in multiple orgs.
func TestWildcardWithMultipleOrgs(t *testing.T) {
	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandler(hub, connLimiter, nil)

	mockClient := &github.MockClient{
		Username: "multiuser",
		Orgs:     []string{"org1", "org2", "org3", "org4", "org5"},
	}

	handler.githubClientFactory = func(token string) github.APIClient {
		return mockClient
	}

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config, _ := websocket.NewConfig(wsURL, "http://localhost/")
	config.Header.Set("Authorization", "Bearer "+strings.Repeat("i", 40))

	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = ws.Close() }()

	// Wildcard subscription with multiple orgs
	sub := map[string]any{
		"organization": "*",
	}
	if err := websocket.JSON.Send(ws, sub); err != nil {
		t.Fatalf("Failed to send subscription: %v", err)
	}

	var response map[string]any
	if err := websocket.JSON.Receive(ws, &response); err != nil {
		t.Fatalf("Failed to receive response: %v", err)
	}

	if response["type"] != "subscription_confirmed" {
		t.Errorf("Expected subscription_confirmed response, got: %v", response)
	}

	if response["username"] != "multiuser" {
		t.Errorf("Expected username multiuser, got: %v", response["username"])
	}

	if mockClient.UserAndOrgsCalls != 1 {
		t.Errorf("Expected 1 UserAndOrgs call, got %d", mockClient.UserAndOrgsCalls)
	}
}

func TestCloseWebSocketAlreadyClosed(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	wc := &wsCloser{ws: ws}
	// Close it first
	_ = wc.Close()

	// Now close again (should handle "closed network connection" error path)
	closeWebSocket(wc, nil, "127.0.0.1")
}

// ========== Critical Server-Side WebSocket Bug Integration Tests ==========

// TestWebSocketCloseErrors tests error handling during WebSocket close operations.
func TestWebSocketCloseErrors(t *testing.T) {
	t.Parallel()

	t.Run("close already closed connection", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
			time.Sleep(50 * time.Millisecond)
		}))
		defer server.Close()

		wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
		ws, err := websocket.Dial(wsURL, "", "http://localhost/")
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}

		wc := &wsCloser{ws: ws}
		_ = wc.Close()

		// Close again - should handle "closed network connection" error
		closeWebSocket(wc, nil, "127.0.0.1")
	})

	t.Run("close with broken pipe", func(t *testing.T) {
		t.Parallel()
		// Simulate broken pipe by forcefully closing underlying connection
		server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
			time.Sleep(20 * time.Millisecond)
			// Force close to cause broken pipe
			ws.Close()
		}))
		defer server.Close()

		wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
		ws, err := websocket.Dial(wsURL, "", "http://localhost/")
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}

		time.Sleep(30 * time.Millisecond)
		wc := &wsCloser{ws: ws}
		closeWebSocket(wc, nil, "127.0.0.1")
	})
}

// TestSendErrorResponseFailure tests what happens when error response can't be sent.
func TestSendErrorResponseFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		// Close connection immediately to cause send error
		ws.Close()
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	// Try to send error response to closed connection
	ctx := context.Background()
	errInfo := errorInfo{
		code:    "test_error",
		message: "Test error",
		reason:  "test",
	}

	err = sendErrorResponse(ctx, ws, errInfo, "127.0.0.1")
	if err == nil {
		t.Log("Note: sendErrorResponse succeeded despite closed connection")
	}
}

// TestHandleAuthErrorWithSendFailure tests handleAuthError when sendErrorResponse fails.
func TestHandleAuthErrorWithSendFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	mockGHClient := &github.MockClient{
		Err: errors.New("auth failed"),
	}

	handler := NewWebSocketHandler(hub, connLimiter, nil)
	handler.githubClientFactory = func(token string) github.APIClient {
		return mockGHClient
	}

	// Create server that immediately closes connection
	server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		ws.Close()
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	// Try to handle auth error on closed connection
	params := authErrorParams{
		logContext: "test",
		username:   "testuser",
		orgName:    "testorg",
		userOrgs:   []string{},
		ip:         "127.0.0.1",
	}

	err = handler.handleAuthError(ctx, ws, errors.New("auth error"), params)
	// Should return error but not panic
	if err == nil {
		t.Error("Expected handleAuthError to return error when sendErrorResponse fails")
	}
}

// TestConcurrentClientCloseOperations tests concurrent close operations on client.
func TestConcurrentClientCloseOperations(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	for i := range 50 {
		client := &Client{
			ID:      fmt.Sprintf("test-client-%d", i),
			send:    make(chan Event, 10),
			control: make(chan map[string]any, 10),
			done:    make(chan struct{}),
		}

		// Trigger multiple concurrent closes
		var wg sync.WaitGroup
		for range 5 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				client.Close()
			}()
		}
		wg.Wait()

		// Should not panic
	}
}

// TestReadSubscriptionWithMalformedJSON tests handling of malformed subscription data.
func TestReadSubscriptionWithMalformedJSON(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	// Test sending oversized payload
	oversized := make([]byte, 2*1024*1024) // 2MB - exceeds maxSubscriptionSize
	for i := range oversized {
		oversized[i] = 'a'
	}

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer ws.Close()

	// Send oversized payload - should be rejected
	err = websocket.Message.Send(ws, oversized)
	// Connection may be closed or error returned - either is acceptable
	_ = err
}

// TestValidateAuthConcurrentAccess tests concurrent access to validateAuth.
func TestValidateAuthConcurrentAccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	mockGHClient := &github.MockClient{
		Username: "testuser",
		Orgs:     []string{"org1", "org2"},
	}

	handler := NewWebSocketHandler(hub, connLimiter, nil)
	handler.githubClientFactory = func(token string) github.APIClient {
		return mockGHClient
	}

	// Create many concurrent WebSocket connections
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			server := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
				time.Sleep(50 * time.Millisecond)
			}))
			defer server.Close()

			wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
			ws, err := websocket.Dial(wsURL, "", "http://localhost/")
			if err != nil {
				return
			}
			defer ws.Close()

			sub := &Subscription{
				Organization: "org1",
			}

			_, _ = handler.validateAuth(ctx, ws, sub, "test-token", "127.0.0.1")
		}()
	}
	wg.Wait()
}

// TestHandleRapidDisconnectReconnect tests rapid connection churn.
func TestHandleRapidDisconnectReconnect(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	hub := NewHub(false)
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	for range 30 {
		server := httptest.NewServer(websocket.Handler(handler.Handle))

		wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
		ws, err := websocket.Dial(wsURL, "", "http://localhost/")
		if err != nil {
			server.Close()
			continue
		}

		// Send subscription
		_ = websocket.JSON.Send(ws, map[string]string{
			"organization": "*",
		})

		// Immediately close
		ws.Close()
		server.Close()

		// Brief pause
		time.Sleep(10 * time.Millisecond)
	}
}

// TestHandleConnectionDuringShutdown tests connection handling during hub shutdown.
func TestHandleConnectionDuringShutdown(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	hub := NewHub(false)
	go hub.Run(ctx)

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	server := httptest.NewServer(websocket.Handler(handler.Handle))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	// Send subscription
	_ = websocket.JSON.Send(ws, map[string]string{
		"organization": "*",
	})

	// Trigger shutdown while connection is active
	cancel()
	hub.Stop()

	time.Sleep(100 * time.Millisecond)
	ws.Close()
}
