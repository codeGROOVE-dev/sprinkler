package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeGROOVE-dev/sprinkler/pkg/srv"
)

func TestWebhookHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := srv.NewHub()
	go h.Run(ctx)

	secret := "testsecret"
	handler := NewHandler(h, secret, nil) // nil allows all events

	// Test invalid method
	req := httptest.NewRequest(http.MethodGet, "/webhook", http.NoBody)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}

	// Test valid webhook
	payload := map[string]any{
		"action": "opened",
		"pull_request": map[string]any{
			"html_url": "https://gitsrv.com/user/repo/pull/1",
			"user": map[string]any{
				"login": "testuser",
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "pull_request") //nolint:canonicalheader // GitHub webhook header

	// Add valid signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Test invalid signature
	req = httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "pull_request") //nolint:canonicalheader // GitHub webhook header
	req.Header.Set("X-Hub-Signature-256", "sha256=invalid")

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	// Test check_suite event with PR number (no html_url)
	checkSuitePayload := map[string]any{
		"action": "completed",
		"check_suite": map[string]any{
			"pull_requests": []any{
				map[string]any{
					"number": float64(16),
				},
			},
		},
		"repository": map[string]any{
			"html_url": "https://gitsrv.com/codeGROOVE-dev/slacker",
		},
	}

	body, err = json.Marshal(checkSuitePayload)
	if err != nil {
		t.Fatalf("failed to marshal check_suite payload: %v", err)
	}

	req = httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "check_suite") //nolint:canonicalheader // GitHub webhook header

	// Add valid signature
	mac = hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	signature = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d for check_suite, got %d", http.StatusOK, w.Code)
	}
}

// TestWebhookHandlerEventFiltering tests event type filtering.
func TestWebhookHandlerEventFiltering(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := srv.NewHub()
	go h.Run(ctx)
	defer h.Stop()

	secret := "testsecret"
	// Only allow pull_request events
	handler := NewHandler(h, secret, []string{"pull_request"})

	// Test allowed event
	payload := map[string]any{
		"action": "opened",
		"pull_request": map[string]any{
			"html_url": "https://gitsrv.com/user/repo/pull/1",
		},
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "pull_request") //nolint:canonicalheader // GitHub webhook header

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("allowed event: expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Test disallowed event (check_run)
	req = httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "check_run") //nolint:canonicalheader // GitHub webhook header
	req.Header.Set("X-Hub-Signature-256", signature)

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("disallowed event: expected status %d (silent accept), got %d", http.StatusOK, w.Code)
	}
}

// TestWebhookHandlerPayloadTooLarge tests max payload size enforcement.
func TestWebhookHandlerPayloadTooLarge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := srv.NewHub()
	go h.Run(ctx)
	defer h.Stop()

	secret := "testsecret"
	handler := NewHandler(h, secret, nil)

	// Create payload larger than maxPayloadSize (1MB)
	largePayload := make([]byte, maxPayloadSize+1)
	for i := range largePayload {
		largePayload[i] = 'a'
	}

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(largePayload))
	req.Header.Set("X-GitHub-Event", "pull_request") //nolint:canonicalheader // GitHub webhook header
	req.ContentLength = int64(len(largePayload))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected status %d, got %d", http.StatusRequestEntityTooLarge, w.Code)
	}
}

// TestWebhookHandlerMissingSignature tests missing signature handling.
func TestWebhookHandlerMissingSignature(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := srv.NewHub()
	go h.Run(ctx)
	defer h.Stop()

	secret := "testsecret"
	handler := NewHandler(h, secret, nil)

	payload := map[string]any{"action": "opened"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "pull_request") //nolint:canonicalheader // GitHub webhook header
	// No signature header

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// TestWebhookHandlerInvalidJSON tests invalid JSON payload handling.
func TestWebhookHandlerInvalidJSON(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := srv.NewHub()
	go h.Run(ctx)
	defer h.Stop()

	secret := "testsecret"
	handler := NewHandler(h, secret, nil)

	invalidJSON := []byte("{invalid json")

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(invalidJSON))
	req.Header.Set("X-GitHub-Event", "pull_request") //nolint:canonicalheader // GitHub webhook header

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(invalidJSON)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestWebhookHandlerCheckRunWithCommit tests check_run event with commit SHA.
func TestWebhookHandlerCheckRunWithCommit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := srv.NewHub()
	go h.Run(ctx)
	defer h.Stop()

	secret := "testsecret"
	handler := NewHandler(h, secret, nil)

	// check_run with head_sha
	payload := map[string]any{
		"action": "completed",
		"check_run": map[string]any{
			"head_sha": "abc123def456",
			"pull_requests": []any{
				map[string]any{
					"number": float64(42),
				},
			},
		},
		"repository": map[string]any{
			"html_url": "https://github.com/owner/repo",
		},
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "check_run") //nolint:canonicalheader // GitHub webhook header

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// TestExtractCommitSHA tests commit SHA extraction.
func TestExtractCommitSHA(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		payload   map[string]any
		expected  string
	}{
		{
			name:      "check_run with head_sha",
			eventType: "check_run",
			payload: map[string]any{
				"check_run": map[string]any{
					"head_sha": "abc123",
				},
			},
			expected: "abc123",
		},
		{
			name:      "check_suite with head_sha",
			eventType: "check_suite",
			payload: map[string]any{
				"check_suite": map[string]any{
					"head_sha": "def456",
				},
			},
			expected: "def456",
		},
		{
			name:      "no SHA",
			eventType: "check_run",
			payload:   map[string]any{},
			expected:  "",
		},
		{
			name:      "check_run with invalid type",
			eventType: "check_run",
			payload: map[string]any{
				"check_run": map[string]any{
					"head_sha": 12345, // not a string
				},
			},
			expected: "",
		},
		{
			name:      "wrong event type",
			eventType: "issues",
			payload: map[string]any{
				"check_run": map[string]any{
					"head_sha": "shouldnotextract",
				},
			},
			expected: "",
		},
		{
			name:      "pull_request with head.sha",
			eventType: "pull_request",
			payload: map[string]any{
				"pull_request": map[string]any{
					"head": map[string]any{
						"sha": "pr_commit_123",
					},
				},
			},
			expected: "pr_commit_123",
		},
		{
			name:      "pull_request without head",
			eventType: "pull_request",
			payload: map[string]any{
				"pull_request": map[string]any{
					"number": 42,
				},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCommitSHA(tt.eventType, tt.payload)
			if result != tt.expected {
				t.Errorf("extractCommitSHA() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestGetMapKeys tests the getMapKeys utility function.
func TestGetMapKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		expected int // Just check length since order is undefined
	}{
		{
			name:     "empty map",
			input:    map[string]any{},
			expected: 0,
		},
		{
			name: "single key",
			input: map[string]any{
				"key1": "value1",
			},
			expected: 1,
		},
		{
			name: "multiple keys",
			input: map[string]any{
				"key1": "value1",
				"key2": "value2",
				"key3": "value3",
			},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getMapKeys(tt.input)
			if len(result) != tt.expected {
				t.Errorf("getMapKeys() returned %d keys, want %d", len(result), tt.expected)
			}
		})
	}
}

// TestWebhookHandlerNoPRURL tests events with no PR URL.
func TestWebhookHandlerNoPRURL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := srv.NewHub()
	go h.Run(ctx)
	defer h.Stop()

	secret := "testsecret"
	handler := NewHandler(h, secret, nil)

	// Event with no PR URL (e.g., push event)
	payload := map[string]any{
		"action": "push",
		"ref":    "refs/heads/main",
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "push") //nolint:canonicalheader // GitHub webhook header

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	// Should return 200 but not broadcast anything
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// TestWebhookHandlerCheckEventWithEmptyPRArray tests check events with empty pull_requests array.
func TestWebhookHandlerCheckEventWithEmptyPRArray(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := srv.NewHub()
	go h.Run(ctx)
	defer h.Stop()

	secret := "testsecret"
	handler := NewHandler(h, secret, nil)

	// check_run with empty pull_requests array
	payload := map[string]any{
		"action": "completed",
		"check_run": map[string]any{
			"head_sha":      "abc123",
			"pull_requests": []any{}, // Empty array
		},
		"repository": map[string]any{
			"html_url": "https://github.com/owner/repo",
		},
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "check_run") //nolint:canonicalheader // GitHub webhook header

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// TestExtractPRURLVariations tests various PR URL extraction scenarios.
func TestExtractPRURLVariations(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		eventType string
		payload   map[string]any
		wantURL   string
	}{
		{
			name:      "pull_request with html_url",
			eventType: "pull_request",
			payload: map[string]any{
				"pull_request": map[string]any{
					"html_url": "https://github.com/owner/repo/pull/123",
				},
			},
			wantURL: "https://github.com/owner/repo/pull/123",
		},
		{
			name:      "check_run with single PR",
			eventType: "check_run",
			payload: map[string]any{
				"check_run": map[string]any{
					"pull_requests": []any{
						map[string]any{
							"number": float64(456),
						},
					},
				},
				"repository": map[string]any{
					"html_url": "https://github.com/owner/repo",
				},
			},
			wantURL: "https://github.com/owner/repo/pull/456",
		},
		{
			name:      "check_suite with PR",
			eventType: "check_suite",
			payload: map[string]any{
				"check_suite": map[string]any{
					"pull_requests": []any{
						map[string]any{
							"number": float64(789),
						},
					},
				},
				"repository": map[string]any{
					"html_url": "https://github.com/owner/repo",
				},
			},
			wantURL: "https://github.com/owner/repo/pull/789",
		},
		{
			name:      "event with no PR data",
			eventType: "push",
			payload: map[string]any{
				"ref": "refs/heads/main",
			},
			wantURL: "",
		},
		{
			name:      "check_run with missing repository",
			eventType: "check_run",
			payload: map[string]any{
				"check_run": map[string]any{
					"pull_requests": []any{
						map[string]any{
							"number": float64(100),
						},
					},
				},
				// No repository field
			},
			wantURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractPRURL(ctx, tt.eventType, tt.payload)
			if result != tt.wantURL {
				t.Errorf("ExtractPRURL() = %q, want %q", result, tt.wantURL)
			}
		})
	}
}
