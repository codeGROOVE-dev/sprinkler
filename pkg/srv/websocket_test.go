package srv

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/codeGROOVE-dev/sprinkler/pkg/security"
)

// TestValidateTokenFormat tests token format validation.
func TestValidateTokenFormat(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{
			name:  "valid ghp token",
			token: "ghp_" + strings.Repeat("a", 36),
			want:  true,
		},
		{
			name:  "valid gho token",
			token: "gho_" + strings.Repeat("b", 36),
			want:  true,
		},
		{
			name:  "valid ghs token",
			token: "ghs_" + strings.Repeat("c", 36),
			want:  true,
		},
		{
			name:  "valid 40-char classic token",
			token: strings.Repeat("d", 40),
			want:  true,
		},
		{
			name:  "valid fine-grained PAT",
			token: "github_pat_" + strings.Repeat("e", 36),
			want:  true,
		},
		{
			name:  "too short",
			token: "ghp_short",
			want:  false,
		},
		{
			name:  "empty token",
			token: "",
			want:  false,
		},
		{
			name:  "invalid characters",
			token: "ghp_" + strings.Repeat("!", 36),
			want:  false,
		},
		{
			name:  "wrong prefix length",
			token: "ghp_" + strings.Repeat("a", 35),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateTokenFormat(tt.token)
			if got != tt.want {
				t.Errorf("validateTokenFormat(%q) = %v, want %v", tt.token, got, tt.want)
			}
		})
	}
}

// TestPreValidateAuth tests the PreValidateAuth method.
func TestPreValidateAuth(t *testing.T) {
	ctx := context.Background()
	hub := NewHub()
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
			req := httptest.NewRequest(http.MethodGet, "/ws", nil)
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
	hub := NewHub()
	go hub.Run(ctx)
	defer hub.Stop()

	connLimiter := security.NewConnectionLimiter(10, 50)
	defer connLimiter.Stop()

	handler := NewWebSocketHandlerForTest(hub, connLimiter, nil)

	// Even with no auth header, test mode should return true
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	got := handler.PreValidateAuth(req)
	if !got {
		t.Error("PreValidateAuth() in test mode should return true")
	}
}

// TestWebSocketHandlerWithMockConnection tests the full WebSocket handler lifecycle.
func TestWebSocketHandlerWithMockConnection(t *testing.T) {
	ctx := context.Background()
	hub := NewHub()
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
	defer ws.Close()

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
	hub := NewHub()
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
	for i := 0; i < 10; i++ {
		go func() {
			_ = wc.Close() // Should not panic
		}()
	}

	time.Sleep(10 * time.Millisecond)
}

// TestExtractGitHubTokenTestMode tests token extraction in test mode.
func TestExtractGitHubTokenTestMode(t *testing.T) {
	ctx := context.Background()
	hub := NewHub()
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
	defer ws.Close()

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
	hub := NewHub()
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
	defer ws.Close()

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

