package main

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
)

func TestVerifySignature(t *testing.T) {
	tests := []struct {
		name      string
		payload   []byte
		signature string
		secret    string
		want      bool
	}{
		{
			name:      "valid signature",
			payload:   []byte(`{"test": "data"}`),
			signature: "sha256=",
			secret:    "mysecret",
			want:      true,
		},
		{
			name:      "invalid signature",
			payload:   []byte(`{"test": "data"}`),
			signature: "sha256=invalid",
			secret:    "mysecret",
			want:      false,
		},
		{
			name:      "missing sha256 prefix",
			payload:   []byte(`{"test": "data"}`),
			signature: "invalid",
			secret:    "mysecret",
			want:      false,
		},
		{
			name:      "empty secret allows any signature",
			payload:   []byte(`{"test": "data"}`),
			signature: "sha256=anything",
			secret:    "",
			want:      true,
		},
	}

	// Fix the first test with correct signature
	mac := hmac.New(sha256.New, []byte("mysecret"))
	mac.Write([]byte(`{"test": "data"}`))
	tests[0].signature = "sha256=" + hex.EncodeToString(mac.Sum(nil))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verifySignature(tt.payload, tt.signature, tt.secret); got != tt.want {
				t.Errorf("verifySignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatches(t *testing.T) {
	tests := []struct {
		name    string
		sub     Subscription
		event   Event
		payload map[string]interface{}
		want    bool
	}{
		{
			name:    "no filters matches nothing",
			sub:     Subscription{},
			event:   Event{URL: "https://github.com/user/repo/pull/1"},
			payload: map[string]interface{}{},
			want:    false,
		},
		{
			name:    "URL exact match",
			sub:     Subscription{PRURL: "https://github.com/user/repo/pull/1"},
			event:   Event{URL: "https://github.com/user/repo/pull/1"},
			payload: map[string]interface{}{},
			want:    true,
		},
		{
			name:    "URL no match",
			sub:     Subscription{PRURL: "https://github.com/user/repo/pull/2"},
			event:   Event{URL: "https://github.com/user/repo/pull/1"},
			payload: map[string]interface{}{},
			want:    false,
		},
		{
			name:  "repository match",
			sub:   Subscription{Repository: "https://github.com/user/repo"},
			event: Event{},
			payload: map[string]interface{}{
				"repository": map[string]interface{}{
					"html_url": "https://github.com/user/repo",
				},
			},
			want: true,
		},
		{
			name:  "username matches PR author",
			sub:   Subscription{Username: "alice"},
			event: Event{},
			payload: map[string]interface{}{
				"pull_request": map[string]interface{}{
					"user": map[string]interface{}{
						"login": "alice",
					},
				},
			},
			want: true,
		},
		{
			name:  "username matches assignee",
			sub:   Subscription{Username: "bob"},
			event: Event{},
			payload: map[string]interface{}{
				"pull_request": map[string]interface{}{
					"assignees": []interface{}{
						map[string]interface{}{"login": "alice"},
						map[string]interface{}{"login": "bob"},
					},
				},
			},
			want: true,
		},
		{
			name:  "username matches reviewer",
			sub:   Subscription{Username: "charlie"},
			event: Event{},
			payload: map[string]interface{}{
				"pull_request": map[string]interface{}{
					"requested_reviewers": []interface{}{
						map[string]interface{}{"login": "charlie"},
					},
				},
			},
			want: true,
		},
		{
			name:  "username matches comment author",
			sub:   Subscription{Username: "dave"},
			event: Event{},
			payload: map[string]interface{}{
				"comment": map[string]interface{}{
					"user": map[string]interface{}{
						"login": "dave",
					},
				},
			},
			want: true,
		},
		{
			name:  "username mentioned in comment",
			sub:   Subscription{Username: "eve"},
			event: Event{},
			payload: map[string]interface{}{
				"comment": map[string]interface{}{
					"body": "Hey @eve, please review this",
				},
			},
			want: true,
		},
		{
			name:  "username matches sender",
			sub:   Subscription{Username: "frank"},
			event: Event{},
			payload: map[string]interface{}{
				"sender": map[string]interface{}{
					"login": "frank",
				},
			},
			want: true,
		},
		{
			name:  "multiple filters - at least one matches",
			sub:   Subscription{Username: "alice", Repository: "https://github.com/user/repo"},
			event: Event{},
			payload: map[string]interface{}{
				"repository": map[string]interface{}{
					"html_url": "https://github.com/user/repo",
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matches(tt.sub, tt.event, tt.payload); got != tt.want {
				t.Errorf("matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractPRURL(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		payload   map[string]interface{}
		want      string
	}{
		{
			name:      "pull_request event",
			eventType: "pull_request",
			payload: map[string]interface{}{
				"pull_request": map[string]interface{}{
					"html_url": "https://github.com/user/repo/pull/1",
				},
			},
			want: "https://github.com/user/repo/pull/1",
		},
		{
			name:      "issue_comment on PR",
			eventType: "issue_comment",
			payload: map[string]interface{}{
				"issue": map[string]interface{}{
					"html_url":     "https://github.com/user/repo/pull/2",
					"pull_request": map[string]interface{}{},
				},
			},
			want: "https://github.com/user/repo/pull/2",
		},
		{
			name:      "issue_comment on issue (not PR)",
			eventType: "issue_comment",
			payload: map[string]interface{}{
				"issue": map[string]interface{}{
					"html_url": "https://github.com/user/repo/issues/3",
				},
			},
			want: "",
		},
		{
			name:      "check_run with PR",
			eventType: "check_run",
			payload: map[string]interface{}{
				"check_run": map[string]interface{}{
					"pull_requests": []interface{}{
						map[string]interface{}{
							"html_url": "https://github.com/user/repo/pull/4",
						},
					},
				},
			},
			want: "https://github.com/user/repo/pull/4",
		},
		{
			name:      "check_suite with PR",
			eventType: "check_suite",
			payload: map[string]interface{}{
				"check_suite": map[string]interface{}{
					"pull_requests": []interface{}{
						map[string]interface{}{
							"html_url": "https://github.com/user/repo/pull/5",
						},
					},
				},
			},
			want: "https://github.com/user/repo/pull/5",
		},
		{
			name:      "unsupported event type",
			eventType: "push",
			payload:   map[string]interface{}{},
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractPRURL(tt.eventType, tt.payload); got != tt.want {
				t.Errorf("extractPRURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

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

	if len(hub.clients) != 2 {
		t.Errorf("expected 2 clients, got %d", len(hub.clients))
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

	if len(hub.clients) != 1 {
		t.Errorf("expected 1 client after unregister, got %d", len(hub.clients))
	}
}

func TestWebhookHandler(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	secret := "testsecret"
	handler := webhookHandler(hub, secret)

	// Test invalid method
	req := httptest.NewRequest(http.MethodGet, "/webhook", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}

	// Test valid webhook
	payload := map[string]interface{}{
		"action": "opened",
		"pull_request": map[string]interface{}{
			"html_url": "https://github.com/user/repo/pull/1",
			"user": map[string]interface{}{
				"login": "testuser",
			},
		},
	}

	body, _ := json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "pull_request")

	// Add valid signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Test invalid signature
	req = httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", "sha256=invalid")

	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestMatchesUser(t *testing.T) {
	tests := []struct {
		name     string
		username string
		payload  map[string]interface{}
		want     bool
	}{
		{
			name:     "no match",
			username: "alice",
			payload:  map[string]interface{}{},
			want:     false,
		},
		{
			name:     "review author match",
			username: "reviewer",
			payload: map[string]interface{}{
				"review": map[string]interface{}{
					"user": map[string]interface{}{
						"login": "reviewer",
					},
				},
			},
			want: true,
		},
		{
			name:     "mention with @ symbol",
			username: "mentioned",
			payload: map[string]interface{}{
				"comment": map[string]interface{}{
					"body": "Thanks @mentioned for the review!",
				},
			},
			want: true,
		},
		{
			name:     "partial username no match",
			username: "alice",
			payload: map[string]interface{}{
				"comment": map[string]interface{}{
					"body": "Thanks @alicewonderland for the review!",
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesUser(tt.username, tt.payload); got != tt.want {
				t.Errorf("matchesUser() = %v, want %v", got, tt.want)
			}
		})
	}
}


