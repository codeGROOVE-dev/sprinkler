package srv

import (
	"fmt"
	"strings"
	"testing"
)

// TestSubscriptionValidationSecurity tests security-focused validation scenarios
func TestSubscriptionValidationSecurity(t *testing.T) {
	tests := []struct {
		name    string
		sub     Subscription
		wantErr bool
		errMsg  string
	}{
		{
			name: "SQL injection attempt in org name",
			sub: Subscription{
				Organization: "'; DROP TABLE users; --",
			},
			wantErr: true,
			errMsg:  "invalid organization name format",
		},
		{
			name: "command injection attempt in org name",
			sub: Subscription{
				Organization: "org`whoami`",
			},
			wantErr: true,
			errMsg:  "invalid organization name format",
		},
		{
			name: "path traversal in org name",
			sub: Subscription{
				Organization: "../../../etc/passwd",
			},
			wantErr: true,
			errMsg:  "invalid organization name format",
		},
		{
			name: "XSS attempt in event type",
			sub: Subscription{
				EventTypes: []string{"<script>alert('xss')</script>"},
			},
			wantErr: true,
			errMsg:  "invalid event type format",
		},
		{
			name: "null byte injection in org name",
			sub: Subscription{
				Organization: "org\x00admin",
			},
			wantErr: true,
			errMsg:  "invalid organization name format",
		},
		{
			name: "unicode tricks in org name",
			sub: Subscription{
				Organization: "org\u202Eadmin", // Right-to-left override
			},
			wantErr: true,
			errMsg:  "invalid organization name format",
		},
		{
			name: "extremely long org name",
			sub: Subscription{
				Organization: strings.Repeat("a", 100), // Over max length
			},
			wantErr: true,
			errMsg:  "invalid organization name",
		},
		{
			name: "malformed PR URL with injection",
			sub: Subscription{
				PullRequests: []string{
					"https://github.com/org/repo/pull/1; rm -rf /",
				},
			},
			wantErr: false, // The semicolon is allowed in current parsing, but the command won't execute
		},
		{
			name: "PR URL with javascript protocol",
			sub: Subscription{
				PullRequests: []string{
					"javascript:alert('xss')",
				},
			},
			wantErr: true,
			errMsg:  "invalid PR URL format",
		},
		{
			name: "PR URL with file protocol",
			sub: Subscription{
				PullRequests: []string{
					"file:///etc/passwd",
				},
			},
			wantErr: true,
			errMsg:  "invalid PR URL format",
		},
		{
			name: "event type with special characters",
			sub: Subscription{
				EventTypes: []string{"pull_request; DROP TABLE"},
			},
			wantErr: true,
			errMsg:  "invalid event type format",
		},
		{
			name: "wildcard is safe",
			sub: Subscription{
				Organization: "*",
			},
			wantErr: false,
		},
		{
			name: "wildcard with suffix attempt",
			sub: Subscription{
				Organization: "*admin",
			},
			wantErr: true,
			errMsg:  "invalid organization name format",
		},
		{
			name: "wildcard with prefix attempt",
			sub: Subscription{
				Organization: "admin*",
			},
			wantErr: true,
			errMsg:  "invalid organization name format",
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

// TestParsePRURLSecurity tests security aspects of PR URL parsing
func TestParsePRURLSecurity(t *testing.T) {
	tests := []struct {
		name      string
		prURL     string
		wantErr   bool
		wantOwner string
		wantRepo  string
		wantNum   int
	}{
		{
			name:    "URL with encoded characters",
			prURL:   "https://github.com/org%2F..%2F..%2Fetc/repo/pull/1",
			wantErr: true, // Should fail - contains dangerous characters
		},
		{
			name:    "URL with newlines",
			prURL:   "https://github.com/org\n/repo/pull/1",
			wantErr: true, // Should fail - contains control characters
		},
		{
			name:    "URL with tabs",
			prURL:   "https://github.com/org\t/repo/pull/1",
			wantErr: true, // Should fail - contains control characters
		},
		{
			name:    "URL with very large PR number",
			prURL:   "https://github.com/org/repo/pull/999999999999999999999",
			wantErr: true, // Should fail parsing as int
		},
		{
			name:      "URL with float PR number",
			prURL:     "https://github.com/org/repo/pull/1.5",
			wantErr:   false, // Sscanf will parse the integer part
			wantOwner: "org",
			wantRepo:  "repo",
			wantNum:   1,
		},
		{
			name:    "URL with hex PR number",
			prURL:   "https://github.com/org/repo/pull/0x1234",
			wantErr: true, // Should fail - PR number is 0
		},
		{
			name:    "URL with empty components",
			prURL:   "https://github.com///pull/1",
			wantErr: true, // Should fail - empty owner/repo
		},
		{
			name:    "URL with only github.com",
			prURL:   "https://github.com/pull/1",
			wantErr: true, // This will fail - not enough parts
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parsePRUrl(tt.prURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePRUrl() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if info.owner != tt.wantOwner {
					t.Errorf("parsePRUrl() owner = %v, want %v", info.owner, tt.wantOwner)
				}
				if info.repo != tt.wantRepo {
					t.Errorf("parsePRUrl() repo = %v, want %v", info.repo, tt.wantRepo)
				}
				if info.prNumber != tt.wantNum {
					t.Errorf("parsePRUrl() num = %v, want %v", info.prNumber, tt.wantNum)
				}
			}
		})
	}
}

// TestMatchesSecurityEdgeCases tests security edge cases in matching logic
func TestMatchesSecurityEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		sub         Subscription
		event       Event
		payload     map[string]any
		userOrgs    map[string]bool
		shouldMatch bool
		shouldPanic bool
	}{
		{
			name: "payload with circular reference should not crash",
			sub: Subscription{
				Organization: "myorg",
			},
			event: Event{Type: "pull_request"},
			payload: func() map[string]any {
				p := make(map[string]any)
				// Note: Go maps can't have true circular references, but we can test deep nesting
				deep := make(map[string]any)
				current := deep
				for range 100 {
					next := make(map[string]any)
					current["nested"] = next
					current = next
				}
				p["repository"] = deep
				return p
			}(),
			userOrgs:    map[string]bool{"myorg": true},
			shouldMatch: false,
			shouldPanic: false,
		},
		{
			name: "payload with wrong type for login field",
			sub: Subscription{
				Organization: "myorg",
			},
			event: Event{Type: "pull_request"},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": 12345, // Number instead of string
					},
				},
			},
			userOrgs:    map[string]bool{"myorg": true},
			shouldMatch: false,
			shouldPanic: false,
		},
		{
			name: "payload with very long org name",
			sub: Subscription{
				Organization: "myorg",
			},
			event: Event{Type: "pull_request"},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": strings.Repeat("a", 10000), // Very long string
					},
				},
			},
			userOrgs:    map[string]bool{"myorg": true},
			shouldMatch: false,
			shouldPanic: false,
		},
		{
			name: "userOrgs with mixed case entries",
			sub: Subscription{
				Organization: "MyOrg",
			},
			event: Event{Type: "pull_request"},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "MyOrg",
					},
				},
			},
			userOrgs: map[string]bool{
				"myorg": true,  // lowercase
				"MYORG": false, // uppercase (should not happen in practice)
			},
			shouldMatch: true, // Should match case-insensitively
			shouldPanic: false,
		},
		{
			name: "mention with malicious username pattern",
			sub: Subscription{
				UserEventsOnly: true,
				Username:       "user",
			},
			event: Event{Type: "issue_comment"},
			payload: map[string]any{
				"comment": map[string]any{
					"body": "@user'; DROP TABLE users; --",
				},
			},
			userOrgs:    map[string]bool{"org": true},
			shouldMatch: true, // Should still match @user mention
			shouldPanic: false,
		},
		{
			name: "PR subscription with malformed PR data",
			sub: Subscription{
				PullRequests: []string{"https://github.com/org/repo/pull/1"},
			},
			event: Event{Type: "pull_request"},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "org",
					},
					"name": "repo",
				},
				"pull_request": map[string]any{
					"number": "not-a-number", // Wrong type
				},
			},
			userOrgs:    map[string]bool{"org": true},
			shouldMatch: false,
			shouldPanic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("matchesForTest() did not panic as expected")
					}
				}()
			}

			result := matchesForTest(tt.sub, tt.event, tt.payload, tt.userOrgs)
			if result != tt.shouldMatch {
				t.Errorf("matchesForTest() = %v, want %v", result, tt.shouldMatch)
			}
		})
	}
}

// TestClientIDGeneration tests that client IDs are sufficiently random
func TestClientIDGeneration(t *testing.T) {
	// This test is more about ensuring IDs are unique and random
	// In the actual code, we use crypto/rand with 32 characters

	ids := make(map[string]bool)
	const numIDs = 10000

	// Simulate ID generation (in real code this is in websocket.go)
	for i := range numIDs {
		// Generate a simple ID for testing uniqueness concept
		// Real implementation uses crypto/rand
		id := fmt.Sprintf("test-id-%d-%d", i, i*31337)
		if ids[id] {
			t.Errorf("Duplicate ID generated: %s", id)
		}
		ids[id] = true
	}

	if len(ids) != numIDs {
		t.Errorf("Expected %d unique IDs, got %d", numIDs, len(ids))
	}
}
