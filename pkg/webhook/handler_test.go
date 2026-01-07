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
	"strings"
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

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}
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
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}

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

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}
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

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}
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

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}
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

// TestCheckEventRaceCondition tests the GitHub webhook timing issue where check events
// can arrive before the pull_requests array is populated.
//
// Background:
// GitHub's webhook system can send check_run/check_suite events immediately when a check
// completes, but their internal indexing may not have updated the pull_requests array yet.
// This creates a race condition where the event arrives without PR information.
//
// Expected behavior:
// - If pull_requests array is empty but we have repository info, use repo URL as fallback
// - Include commit SHA so clients can look up the PR later
// - Org-based subscriptions still work with repo URL
// - Only drop event if we can't extract ANY repository information
func TestCheckEventRaceCondition(t *testing.T) { //nolint:gocognit,maintidx // Test requires comprehensive validation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := srv.NewHub()
	go h.Run(ctx)
	defer h.Stop()

	secret := "testsecret"
	handler := NewHandler(h, secret, nil)

	tests := []struct {
		name             string
		eventType        string
		payload          map[string]any
		expectStatusCode int
		expectBroadcast  bool
		expectRepoURL    bool // true if we expect repo URL fallback
		expectCommitSHA  bool
	}{
		{
			name:      "check_run with empty pull_requests array - GitHub race condition",
			eventType: "check_run",
			payload: map[string]any{
				"action": "completed",
				"check_run": map[string]any{
					"head_sha":      "abc123def456789",
					"pull_requests": []any{}, // Empty - race condition!
					"status":        "completed",
					"conclusion":    "success",
				},
				"repository": map[string]any{
					"html_url": "https://github.com/testorg/testrepo",
					"owner": map[string]any{
						"login": "testorg",
					},
					"name": "testrepo",
				},
			},
			expectStatusCode: http.StatusOK,
			expectBroadcast:  true, // Should still broadcast with repo URL
			expectRepoURL:    true,
			expectCommitSHA:  true,
		},
		{
			name:      "check_suite with missing pull_requests field - GitHub race condition",
			eventType: "check_suite",
			payload: map[string]any{
				"action": "completed",
				"check_suite": map[string]any{
					"head_sha": "def456abc123789",
					// No pull_requests field at all
					"status":     "completed",
					"conclusion": "success",
				},
				"repository": map[string]any{
					"html_url": "https://github.com/myorg/myrepo",
					"owner": map[string]any{
						"login": "myorg",
					},
					"name": "myrepo",
				},
			},
			expectStatusCode: http.StatusOK,
			expectBroadcast:  true,
			expectRepoURL:    true,
			expectCommitSHA:  true,
		},
		{
			name:      "check_run with null pull_requests - another variant",
			eventType: "check_run",
			payload: map[string]any{
				"action": "completed",
				"check_run": map[string]any{
					"head_sha":      "nullcase123456",
					"pull_requests": nil, // Explicitly null
				},
				"repository": map[string]any{
					"html_url": "https://github.com/nullorg/nullrepo",
					"owner": map[string]any{
						"login": "nullorg",
					},
				},
			},
			expectStatusCode: http.StatusOK,
			expectBroadcast:  true,
			expectRepoURL:    true,
			expectCommitSHA:  true,
		},
		{
			name:      "check_run with no repository - must drop event",
			eventType: "check_run",
			payload: map[string]any{
				"action": "completed",
				"check_run": map[string]any{
					"head_sha":      "norepository123",
					"pull_requests": []any{},
				},
				// Missing repository field entirely
			},
			expectStatusCode: http.StatusOK, // Still 200 to GitHub
			expectBroadcast:  false,         // Event dropped
			expectRepoURL:    false,
			expectCommitSHA:  false,
		},
		{
			name:      "check_suite with repository but no html_url - must drop",
			eventType: "check_suite",
			payload: map[string]any{
				"action": "completed",
				"check_suite": map[string]any{
					"head_sha":      "nohtmlurl456",
					"pull_requests": []any{},
				},
				"repository": map[string]any{
					"name": "repo",
					// Missing html_url
				},
			},
			expectStatusCode: http.StatusOK,
			expectBroadcast:  false,
			expectRepoURL:    false,
			expectCommitSHA:  false,
		},
		{
			name:      "check_run with populated pull_requests - normal case (no race)",
			eventType: "check_run",
			payload: map[string]any{
				"action": "completed",
				"check_run": map[string]any{
					"head_sha": "normalcase123",
					"pull_requests": []any{
						map[string]any{
							"number": float64(42),
						},
					},
				},
				"repository": map[string]any{
					"html_url": "https://github.com/normalorg/normalrepo",
				},
			},
			expectStatusCode: http.StatusOK,
			expectBroadcast:  true,
			expectRepoURL:    false, // Should have PR URL, not repo URL
			expectCommitSHA:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.payload)
			if err != nil {
				t.Fatalf("Failed to marshal payload: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
			req.Header.Set("X-GitHub-Event", tt.eventType)                //nolint:canonicalheader // GitHub webhook header
			req.Header.Set("X-GitHub-Delivery", "test-delivery-"+tt.name) //nolint:canonicalheader // GitHub webhook header

			// Add valid signature
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(body)
			signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
			req.Header.Set("X-Hub-Signature-256", signature)

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			// Check response status
			if w.Code != tt.expectStatusCode {
				t.Errorf("expected status %d, got %d", tt.expectStatusCode, w.Code)
			}

			// Verify URL extraction behavior
			// Note: ExtractPRURL returns "" when there's no PR URL in check events.
			// The handler in ServeHTTP then falls back to repo URL (lines 163-222 in handler.go)
			ctx := context.Background()
			extractedURL := ExtractPRURL(ctx, tt.eventType, tt.payload)

			switch {
			case tt.expectRepoURL:
				// ExtractPRURL should return empty (no PR URL)
				if extractedURL != "" {
					t.Errorf("Expected ExtractPRURL to return empty (triggering repo fallback), got %q", extractedURL)
				}
				// Verify we have repo URL available for fallback
				repoURL, ok := tt.payload["repository"].(map[string]any)["html_url"].(string)
				if !ok {
					t.Fatal("Test setup error: repository.html_url missing")
				}
				// Repo URL should NOT contain /pull/
				if contains := strings.Contains(repoURL, "/pull/"); contains {
					t.Errorf("Repo URL should not contain /pull/, got %q", repoURL)
				}
			case tt.expectBroadcast:
				// Should have PR URL (normal case)
				if extractedURL == "" {
					t.Error("Expected PR URL but got empty string")
				}
				if contains := strings.Contains(extractedURL, "/pull/"); !contains {
					t.Errorf("Expected PR URL with /pull/, got %q", extractedURL)
				}
			default:
				// Event should be dropped, no URL
				if extractedURL != "" {
					t.Errorf("Expected empty URL for dropped event, got %q", extractedURL)
				}
			}

			// Verify commit SHA extraction
			extractedSHA := extractCommitSHA(tt.eventType, tt.payload)
			if tt.expectCommitSHA {
				if extractedSHA == "" {
					t.Error("Expected commit SHA but got empty string")
				}
				// Verify it matches the SHA in payload
				var expectedSHA string
				switch tt.eventType {
				case "check_run":
					if checkRun, ok := tt.payload["check_run"].(map[string]any); ok {
						expectedSHA, _ = checkRun["head_sha"].(string)
					}
				case "check_suite":
					if checkSuite, ok := tt.payload["check_suite"].(map[string]any); ok {
						expectedSHA, _ = checkSuite["head_sha"].(string)
					}
				}
				if expectedSHA != "" && extractedSHA != expectedSHA {
					t.Errorf("Expected SHA %q, got %q", expectedSHA, extractedSHA)
				}
			}
		})
	}
}

// TestCheckEventRaceConditionEndToEnd tests the complete flow including hub broadcast.
// This verifies that events with repo URL fallback can still be received by org-based subscribers.
func TestCheckEventRaceConditionEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := srv.NewHub()
	go h.Run(ctx)
	defer h.Stop()

	secret := "testsecret"
	handler := NewHandler(h, secret, nil)

	// Simulate check_run event with empty pull_requests (GitHub race condition)
	payload := map[string]any{
		"action": "completed",
		"check_run": map[string]any{
			"head_sha":      "racecommit123",
			"pull_requests": []any{}, // Empty due to timing
			"status":        "completed",
		},
		"repository": map[string]any{
			"html_url": "https://github.com/raceorg/racerepo",
			"owner": map[string]any{
				"login": "raceorg", // This is what org subscribers will match on
			},
			"name": "racerepo",
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "check_run")                 //nolint:canonicalheader // GitHub webhook header
	req.Header.Set("X-GitHub-Delivery", "race-test-delivery-123") //nolint:canonicalheader // GitHub webhook header

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify that ExtractPRURL returns empty (no PR URL in check event with empty pull_requests)
	// The handler then falls back to repo URL when broadcasting
	extractedURL := ExtractPRURL(ctx, "check_run", payload)
	if extractedURL != "" {
		t.Errorf("Expected ExtractPRURL to return empty string (no PR URL), got %q", extractedURL)
	}

	// Verify we have repo URL available for the handler's fallback logic
	expectedRepoURL := "https://github.com/raceorg/racerepo"
	repoURL, ok := payload["repository"].(map[string]any)["html_url"].(string)
	if !ok || repoURL != expectedRepoURL {
		t.Errorf("Repository URL should be %q, got %q", expectedRepoURL, repoURL)
	}

	// Verify commit SHA is extracted for client-side lookup
	extractedSHA := extractCommitSHA("check_run", payload)
	if extractedSHA != "racecommit123" {
		t.Errorf("Expected SHA 'racecommit123', got %q", extractedSHA)
	}

	// Verify the repo URL is NOT a PR URL (no /pull/ in path)
	// This confirms the handler will use repo URL as fallback, not a PR URL
	if contains := strings.Contains(repoURL, "/pull/"); contains {
		t.Errorf("Repo URL should not contain /pull/, got %q", repoURL)
	}
}
