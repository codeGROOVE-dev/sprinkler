package srv

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// TestWildcardOrganizationEdgeCases tests edge cases for wildcard organization subscriptions
func TestWildcardOrganizationEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		subscription Subscription
		eventOrg     string
		userOrgs     map[string]bool
		eventType    string
		payload      map[string]any
		shouldMatch  bool
	}{
		{
			name: "wildcard with empty userOrgs map",
			subscription: Subscription{
				Organization: "*",
				Username:     "testuser",
			},
			eventOrg:  "someorg",
			userOrgs:  map[string]bool{}, // Empty org list
			eventType: "pull_request",
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "someorg",
					},
				},
			},
			shouldMatch: false, // User not member of any org
		},
		{
			name: "wildcard with nil userOrgs map",
			subscription: Subscription{
				Organization: "*",
				Username:     "testuser",
			},
			eventOrg:  "someorg",
			userOrgs:  nil, // Nil map
			eventType: "pull_request",
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "someorg",
					},
				},
			},
			shouldMatch: false,
		},
		{
			name: "wildcard with case mismatch in org names",
			subscription: Subscription{
				Organization: "*",
				Username:     "testuser",
			},
			eventOrg: "MyOrg", // Mixed case
			userOrgs: map[string]bool{
				"myorg": true, // Lowercase in map
			},
			eventType: "pull_request",
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "MyOrg",
					},
				},
			},
			shouldMatch: true, // Should match case-insensitively
		},
		{
			name: "wildcard with event missing org info",
			subscription: Subscription{
				Organization: "*",
				Username:     "testuser",
			},
			eventOrg: "",
			userOrgs: map[string]bool{
				"myorg": true,
			},
			eventType: "pull_request",
			payload: map[string]any{
				// Missing repository/owner info
				"pull_request": map[string]any{
					"id": 123,
				},
			},
			shouldMatch: false, // No org to match against
		},
		{
			name: "wildcard with very large number of orgs",
			subscription: Subscription{
				Organization: "*",
				Username:     "testuser",
			},
			eventOrg: "org500",
			userOrgs: func() map[string]bool {
				orgs := make(map[string]bool, 1000)
				for i := range 1000 {
					orgs[fmt.Sprintf("org%d", i)] = true
				}
				return orgs
			}(),
			eventType: "pull_request",
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "org500",
					},
				},
			},
			shouldMatch: true,
		},
		{
			name: "wildcard combined with PR subscription",
			subscription: Subscription{
				Organization: "*",
				Username:     "testuser",
				PullRequests: []string{"https://github.com/myorg/repo/pull/1"},
			},
			eventOrg: "myorg",
			userOrgs: map[string]bool{
				"myorg": true,
			},
			eventType: "pull_request",
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
					"name": "repo",
				},
				"pull_request": map[string]any{
					"number": float64(2), // Different PR
				},
			},
			shouldMatch: false, // PR doesn't match even though org does
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := Event{
				Type: tt.eventType,
			}

			result := matchesForTest(tt.subscription, event, tt.payload, tt.userOrgs)
			if result != tt.shouldMatch {
				t.Errorf("matchesForTest() = %v, want %v", result, tt.shouldMatch)
			}
		})
	}
}

// TestPRURLValidationEdgeCases tests edge cases for PR URL validation
func TestPRURLValidationEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		sub     Subscription
		wantErr bool
		errMsg  string
	}{
		{
			name: "PR URL at exact max length",
			sub: Subscription{
				PullRequests: []string{
					"https://github.com/" + strings.Repeat("a", 235) + "/" + strings.Repeat("b", 235) + "/pull/1", // Exactly 500 chars
				},
			},
			wantErr: false,
		},
		{
			name: "PR URL exceeds max length",
			sub: Subscription{
				PullRequests: []string{
					"https://github.com/" + strings.Repeat("a", 481) + "/pull/1", // 501 chars
				},
			},
			wantErr: true,
			errMsg:  "PR URL too long",
		},
		{
			name: "PR URL with invalid characters in path",
			sub: Subscription{
				PullRequests: []string{
					"https://github.com/../../etc/passwd/pull/1",
				},
			},
			wantErr: true, // Now fails due to parsePRUrl validation
			errMsg:  "invalid PR URL structure",
		},
		{
			name: "PR URL with unicode characters",
			sub: Subscription{
				PullRequests: []string{
					"https://github.com/用户/仓库/pull/1", //nolint:gosmopolitan // Testing Unicode rejection
				},
			},
			wantErr: true, // Should fail - non-ASCII characters
			errMsg:  "invalid PR URL structure",
		},
		{
			name: "PR URL with spaces",
			sub: Subscription{
				PullRequests: []string{
					"https://github.com/my org/my repo/pull/1",
				},
			},
			wantErr: true, // Should fail - spaces not allowed
			errMsg:  "invalid PR URL structure",
		},
		{
			name: "PR URL with negative number",
			sub: Subscription{
				PullRequests: []string{
					"https://github.com/org/repo/pull/-1",
				},
			},
			wantErr: true,
			errMsg:  "invalid PR URL structure",
		},
		{
			name: "PR URL with zero",
			sub: Subscription{
				PullRequests: []string{
					"https://github.com/org/repo/pull/0",
				},
			},
			wantErr: true,
			errMsg:  "invalid PR URL structure",
		},
		{
			name: "exactly 200 PR URLs",
			sub: Subscription{
				PullRequests: func() []string {
					urls := make([]string, 200)
					for i := range 200 {
						urls[i] = fmt.Sprintf("https://github.com/org/repo/pull/%d", i+1)
					}
					return urls
				}(),
			},
			wantErr: false,
		},
		{
			name: "201 PR URLs",
			sub: Subscription{
				PullRequests: func() []string {
					urls := make([]string, 201)
					for i := range 201 {
						urls[i] = fmt.Sprintf("https://github.com/org/repo/pull/%d", i+1)
					}
					return urls
				}(),
			},
			wantErr: true,
			errMsg:  "too many PR URLs specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sub.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Validate() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

// TestOrganizationLimitEdgeCases tests the 1000 org limit we added for security
func TestOrganizationLimitEdgeCases(t *testing.T) {
	// Create a list of 1500 orgs
	manyOrgs := make([]string, 1500)
	for i := range 1500 {
		manyOrgs[i] = fmt.Sprintf("org%d", i)
	}

	client := NewClientForTest(context.Background(),
		"test-id",
		Subscription{Organization: "*", Username: "testuser"},
		nil,
		nil,
		manyOrgs,
	)

	// Verify only first 1000 orgs are stored
	if len(client.userOrgs) != 1000 {
		t.Errorf("Expected 1000 orgs, got %d", len(client.userOrgs))
	}

	// Verify the first 1000 are present
	for i := range 1000 {
		orgName := fmt.Sprintf("org%d", i)
		if !client.userOrgs[orgName] {
			t.Errorf("Expected org %s to be present", orgName)
		}
	}

	// Verify orgs beyond 1000 are not present
	for i := 1000; i < 1500; i++ {
		orgName := fmt.Sprintf("org%d", i)
		if client.userOrgs[orgName] {
			t.Errorf("Expected org %s to be absent", orgName)
		}
	}
}

// TestConcurrentMapAccess tests for race conditions in map access
func TestConcurrentMapAccess(t *testing.T) {
	hub := NewHub(false)

	for i := range 10 {
		client := NewClientForTest(context.Background(),
			fmt.Sprintf("client%d", i),
			Subscription{
				Organization: "*",
				Username:     fmt.Sprintf("user%d", i),
			},
			nil,
			hub,
			[]string{"org1", "org2", "org3"},
		)
		hub.clients[client.ID] = client
	}

	// Simulate concurrent event broadcasts
	done := make(chan bool)
	for i := range 100 {
		go func(index int) {
			event := Event{
				Type: "pull_request",
				URL:  fmt.Sprintf("https://github.com/org1/repo/pull/%d", index),
			}
			payload := map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "org1",
					},
				},
			}

			// Test concurrent matching
			for _, client := range hub.clients {
				matchesForTest(client.subscription, event, payload, client.userOrgs)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for range 100 {
		<-done
	}
}

// TestChannelBufferOverflow tests behavior when channels are full
func TestChannelBufferOverflow(t *testing.T) {
	hub := NewHub(false)

	// Fill the broadcast channel to capacity
	for i := range broadcastBufferSize {
		msg := broadcastMsg{
			event:   Event{Type: "test"},
			payload: map[string]any{},
		}
		select {
		case hub.broadcast <- msg:
			// Successfully sent
		default:
			t.Errorf("Channel should not be full at message %d", i)
		}
	}

	// Try to send one more - should not block
	extraMsg := broadcastMsg{
		event:   Event{Type: "overflow"},
		payload: map[string]any{},
	}

	select {
	case hub.broadcast <- extraMsg:
		t.Error("Should not be able to send when buffer is full")
	default:
		// Expected - channel is full
	}
}

// TestEmptyEventPayload tests handling of events with missing or malformed payloads
func TestEmptyEventPayload(t *testing.T) {
	tests := []struct {
		name        string
		payload     map[string]any
		sub         Subscription
		shouldMatch bool
	}{
		{
			name:    "nil payload",
			payload: nil,
			sub: Subscription{
				Organization: "myorg",
			},
			shouldMatch: false,
		},
		{
			name:    "empty payload",
			payload: map[string]any{},
			sub: Subscription{
				Organization: "myorg",
			},
			shouldMatch: false,
		},
		{
			name: "payload with nil repository",
			payload: map[string]any{
				"repository": nil,
			},
			sub: Subscription{
				Organization: "myorg",
			},
			shouldMatch: false,
		},
		{
			name: "payload with non-map repository",
			payload: map[string]any{
				"repository": "not-a-map",
			},
			sub: Subscription{
				Organization: "myorg",
			},
			shouldMatch: false,
		},
		{
			name: "payload with repository but nil owner",
			payload: map[string]any{
				"repository": map[string]any{
					"owner": nil,
				},
			},
			sub: Subscription{
				Organization: "myorg",
			},
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := Event{Type: "pull_request"}
			userOrgs := map[string]bool{"myorg": true}

			// This should not panic
			result := matchesForTest(tt.sub, event, tt.payload, userOrgs)
			if result != tt.shouldMatch {
				t.Errorf("matchesForTest() = %v, want %v", result, tt.shouldMatch)
			}
		})
	}
}
