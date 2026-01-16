package srv

import (
	"strings"
	"testing"
)

//nolint:maintidx // Test function with comprehensive test cases
func TestMatches(t *testing.T) {
	tests := []struct {
		name     string
		sub      Subscription
		event    Event
		payload  map[string]any
		userOrgs map[string]bool
		want     bool
	}{
		{
			name:    "no organization matches nothing",
			sub:     Subscription{},
			event:   Event{URL: "https://github.com/myorg/repo/pull/1"},
			payload: map[string]any{},
			want:    false,
		},
		{
			name:  "organization match via repository owner",
			sub:   Subscription{Organization: "myorg"},
			event: Event{URL: "https://github.com/myorg/repo/pull/1"},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
			},
			want: true,
		},
		{
			name:  "organization match case-insensitive",
			sub:   Subscription{Organization: "MyOrg"},
			event: Event{URL: "https://github.com/myorg/repo/pull/1"},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
			},
			want: true,
		},
		{
			name:  "organization no match",
			sub:   Subscription{Organization: "otherorg"},
			event: Event{URL: "https://github.com/myorg/repo/pull/1"},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
			},
			want: false,
		},
		{
			name:  "organization match via organization field",
			sub:   Subscription{Organization: "myorg"},
			event: Event{},
			payload: map[string]any{
				"organization": map[string]any{
					"login": "myorg",
				},
			},
			want: true,
		},
		{
			name:  "my events only - matches PR author",
			sub:   Subscription{Organization: "myorg", UserEventsOnly: true, Username: "alice"},
			event: Event{},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
				"pull_request": map[string]any{
					"user": map[string]any{
						"login": "alice",
					},
				},
			},
			want: true,
		},
		{
			name:  "my events only - no match for different user",
			sub:   Subscription{Organization: "myorg", UserEventsOnly: true, Username: "alice"},
			event: Event{},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
				"pull_request": map[string]any{
					"user": map[string]any{
						"login": "bob",
					},
				},
			},
			want: false,
		},
		{
			name:  "all org events - matches any user",
			sub:   Subscription{Organization: "myorg", UserEventsOnly: false},
			event: Event{},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
				"pull_request": map[string]any{
					"user": map[string]any{
						"login": "bob",
					},
				},
			},
			want: true,
		},
		{
			name:  "my events only - matches assignee",
			sub:   Subscription{Organization: "myorg", UserEventsOnly: true, Username: "alice"},
			event: Event{},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
				"pull_request": map[string]any{
					"user": map[string]any{
						"login": "bob",
					},
					"assignees": []any{
						map[string]any{"login": "alice"},
					},
				},
			},
			want: true,
		},
		{
			name:  "my events only - matches reviewer",
			sub:   Subscription{Organization: "myorg", UserEventsOnly: true, Username: "alice"},
			event: Event{},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
				"pull_request": map[string]any{
					"user": map[string]any{
						"login": "bob",
					},
					"requested_reviewers": []any{
						map[string]any{"login": "alice"},
					},
				},
			},
			want: true,
		},
		{
			name:  "my events only - matches review author",
			sub:   Subscription{Organization: "myorg", UserEventsOnly: true, Username: "alice"},
			event: Event{},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
				"review": map[string]any{
					"user": map[string]any{
						"login": "alice",
					},
				},
			},
			want: true,
		},
		{
			name:  "my events only - matches comment author",
			sub:   Subscription{Organization: "myorg", UserEventsOnly: true, Username: "alice"},
			event: Event{},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
				"comment": map[string]any{
					"user": map[string]any{
						"login": "alice",
					},
					"body": "This looks good",
				},
			},
			want: true,
		},
		{
			name:  "my events only - matches mention",
			sub:   Subscription{Organization: "myorg", UserEventsOnly: true, Username: "alice"},
			event: Event{},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
				"comment": map[string]any{
					"user": map[string]any{
						"login": "bob",
					},
					"body": "Hey @alice, can you review this?",
				},
			},
			want: true,
		},
		{
			name:  "event type filter matches",
			sub:   Subscription{Organization: "myorg", EventTypes: []string{"pull_request", "issue_comment"}},
			event: Event{Type: "pull_request"},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
			},
			want: true,
		},
		{
			name:  "event type filter does not match",
			sub:   Subscription{Organization: "myorg", EventTypes: []string{"pull_request", "issue_comment"}},
			event: Event{Type: "push"},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
			},
			want: false,
		},
		{
			name:  "no event type filter matches any",
			sub:   Subscription{Organization: "myorg"},
			event: Event{Type: "push"},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
			},
			want: true,
		},
		{
			name:  "my events only - matches sender",
			sub:   Subscription{Organization: "myorg", UserEventsOnly: true, Username: "alice"},
			event: Event{},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
				"sender": map[string]any{
					"login": "alice",
				},
			},
			want: true,
		},
		{
			name:  "my events only - user NOT member of event org",
			sub:   Subscription{Organization: "myorg", UserEventsOnly: true, Username: "alice"},
			event: Event{},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "otherorg",
					},
				},
				"sender": map[string]any{
					"login": "alice",
				},
			},
			userOrgs: map[string]bool{"myorg": true}, // User is only member of myorg, not otherorg
			want:     false,                          // Should not receive events from orgs they're not members of
		},
		{
			name:  "my events only - user IS member of event org but filtered by subscription org",
			sub:   Subscription{Organization: "myorg", UserEventsOnly: true, Username: "alice"},
			event: Event{},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "otherorg",
					},
				},
				"sender": map[string]any{
					"login": "alice",
				},
			},
			userOrgs: map[string]bool{"myorg": true, "otherorg": true}, // User is member of both
			want:     false,                                            // Should NOT receive - event is from otherorg but subscription is for myorg
		},
		{
			name:  "my events only - no org specified, receives from all member orgs",
			sub:   Subscription{UserEventsOnly: true, Username: "alice"},
			event: Event{},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "otherorg",
					},
				},
				"sender": map[string]any{
					"login": "alice",
				},
			},
			userOrgs: map[string]bool{"myorg": true, "otherorg": true}, // User is member of both
			want:     true,                                             // Should receive - no org filter, user is member of event's org
		},
		{
			name: "PR subscription - matches subscribed PR",
			sub: Subscription{
				Organization: "myorg",
				PullRequests: []string{
					"https://github.com/myorg/myrepo/pull/123",
					"https://github.com/myorg/myrepo/pull/456",
				},
			},
			event: Event{Type: "pull_request"},
			payload: map[string]any{
				"repository": map[string]any{
					"name": "myrepo",
					"owner": map[string]any{
						"login": "myorg",
					},
				},
				"pull_request": map[string]any{
					"number": float64(123),
				},
			},
			userOrgs: map[string]bool{"myorg": true},
			want:     true,
		},
		{
			name: "PR subscription - does not match different PR",
			sub: Subscription{
				Organization: "myorg",
				PullRequests: []string{
					"https://github.com/myorg/myrepo/pull/123",
				},
			},
			event: Event{Type: "pull_request"},
			payload: map[string]any{
				"repository": map[string]any{
					"name": "myrepo",
					"owner": map[string]any{
						"login": "myorg",
					},
				},
				"pull_request": map[string]any{
					"number": float64(789), // Different PR number
				},
			},
			userOrgs: map[string]bool{"myorg": true},
			want:     false,
		},
		{
			name: "PR subscription - user not member of org",
			sub: Subscription{
				Organization: "myorg",
				PullRequests: []string{
					"https://github.com/otherorg/repo/pull/123",
				},
			},
			event: Event{Type: "pull_request"},
			payload: map[string]any{
				"repository": map[string]any{
					"name": "repo",
					"owner": map[string]any{
						"login": "otherorg",
					},
				},
				"pull_request": map[string]any{
					"number": float64(123),
				},
			},
			userOrgs: map[string]bool{"myorg": true}, // User is NOT member of otherorg
			want:     false,
		},
		{
			name: "PR subscription - matches PR review event",
			sub: Subscription{
				Organization: "myorg",
				PullRequests: []string{
					"https://github.com/myorg/myrepo/pull/42",
				},
			},
			event: Event{Type: "pull_request_review"},
			payload: map[string]any{
				"repository": map[string]any{
					"name": "myrepo",
					"owner": map[string]any{
						"login": "myorg",
					},
				},
				"pull_request": map[string]any{
					"number": float64(42),
				},
			},
			userOrgs: map[string]bool{"myorg": true},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set default userOrgs if not specified
			if tt.userOrgs == nil {
				tt.userOrgs = make(map[string]bool)
				// Add the subscription org as a default for backward compatibility
				if tt.sub.Organization != "" {
					tt.userOrgs[strings.ToLower(tt.sub.Organization)] = true
				}
			}
			got := matchesForTest(tt.sub, tt.event, tt.payload, tt.userOrgs)
			if got != tt.want {
				t.Errorf("matchesForTest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePRUrl(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
		wantNum   int
		wantErr   bool
	}{
		{
			name:      "valid https URL",
			url:       "https://github.com/myorg/myrepo/pull/123",
			wantOwner: "myorg",
			wantRepo:  "myrepo",
			wantNum:   123,
			wantErr:   false,
		},
		{
			name:      "valid http URL",
			url:       "http://github.com/myorg/myrepo/pull/456",
			wantOwner: "myorg",
			wantRepo:  "myrepo",
			wantNum:   456,
			wantErr:   false,
		},
		{
			name:    "invalid - issues URL",
			url:     "https://github.com/myorg/myrepo/issues/123",
			wantErr: true,
		},
		{
			name:    "invalid - missing pull",
			url:     "https://github.com/myorg/myrepo/123",
			wantErr: true,
		},
		{
			name:    "invalid - not a number",
			url:     "https://github.com/myorg/myrepo/pull/abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parsePRUrl(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePRUrl() error = %v, wantErr %v", err, tt.wantErr)
				return
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

func TestValidateSubscription(t *testing.T) {
	tests := []struct {
		name    string
		sub     Subscription
		wantErr bool
	}{
		{
			name:    "valid org",
			sub:     Subscription{Organization: "myorg"},
			wantErr: false,
		},
		{
			name:    "missing organization is allowed",
			sub:     Subscription{},
			wantErr: false,
		},
		{
			name:    "org name too long",
			sub:     Subscription{Organization: string(make([]byte, 40))},
			wantErr: true,
		},
		{
			name:    "invalid org name characters",
			sub:     Subscription{Organization: "my@org"},
			wantErr: true,
		},
		{
			name:    "valid org with underscore",
			sub:     Subscription{Organization: "my_org"},
			wantErr: false,
		},
		{
			name:    "valid org with hyphen",
			sub:     Subscription{Organization: "my-org"},
			wantErr: false,
		},
		{
			name: "all fields valid",
			sub: Subscription{
				Organization:   "myorg",
				UserEventsOnly: true,
			},
			wantErr: false,
		},
		{
			name: "valid with event types",
			sub: Subscription{
				Organization: "myorg",
				EventTypes:   []string{"pull_request", "issue_comment"},
			},
			wantErr: false,
		},
		{
			name: "invalid event type format",
			sub: Subscription{
				Organization: "myorg",
				EventTypes:   []string{"pull-request"}, // hyphen not allowed
			},
			wantErr: true,
		},
		{
			name: "too many event types",
			sub: Subscription{
				Organization: "myorg",
				EventTypes:   make([]string, 51),
			},
			wantErr: true,
		},
		{
			name: "valid PR URLs",
			sub: Subscription{
				Organization: "myorg",
				PullRequests: []string{
					"https://github.com/myorg/repo/pull/123",
					"https://github.com/myorg/repo/pull/456",
				},
			},
			wantErr: false,
		},
		{
			name: "too many PR URLs",
			sub: Subscription{
				Organization: "myorg",
				PullRequests: make([]string, 201), // 201 URLs, over the limit
			},
			wantErr: true,
		},
		{
			name: "invalid PR URL format",
			sub: Subscription{
				Organization: "myorg",
				PullRequests: []string{
					"https://github.com/myorg/repo/issues/123", // issues, not pull
				},
			},
			wantErr: true,
		},
		{
			name: "empty PR URL",
			sub: Subscription{
				Organization: "myorg",
				PullRequests: []string{
					"",
				},
			},
			wantErr: true,
		},
		{
			name: "empty event type in list",
			sub: Subscription{
				Organization: "myorg",
				EventTypes:   []string{"pull_request", ""},
			},
			wantErr: true,
		},
		{
			name: "event type too long",
			sub: Subscription{
				Organization: "myorg",
				EventTypes:   []string{strings.Repeat("a", 101)},
			},
			wantErr: true,
		},
		{
			name: "PR URL with invalid structure - no owner",
			sub: Subscription{
				Organization: "myorg",
				PullRequests: []string{
					"https://github.com//repo/pull/123",
				},
			},
			wantErr: true,
		},
		{
			name: "PR URL with invalid structure - no repo",
			sub: Subscription{
				Organization: "myorg",
				PullRequests: []string{
					"https://github.com/owner//pull/123",
				},
			},
			wantErr: true,
		},
		{
			name: "PR URL with invalid PR number",
			sub: Subscription{
				Organization: "myorg",
				PullRequests: []string{
					"https://github.com/owner/repo/pull/",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sub.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParsePRUrlEdgeCases tests edge cases in PR URL parsing.
func TestParsePRUrlEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		prURL   string
		wantErr bool
	}{
		{
			name:    "invalid repo name with special chars",
			prURL:   "https://github.com/owner/repo@test/pull/123",
			wantErr: true,
		},
		{
			name:    "valid repo with underscores",
			prURL:   "https://github.com/owner/repo_test/pull/123",
			wantErr: false,
		},
		{
			name:    "valid repo with dots",
			prURL:   "https://github.com/owner/repo.test/pull/123",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePRUrl(tt.prURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePRUrl() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestMatchesUserEventsOnlyEdgeCases tests edge cases in UserEventsOnly matching.
func TestMatchesUserEventsOnlyEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		sub      Subscription
		event    Event
		payload  map[string]any
		userOrgs map[string]bool
		want     bool
	}{
		{
			name: "UserEventsOnly with wildcard org - user not a member",
			sub: Subscription{
				Organization:   "*",
				UserEventsOnly: true,
				Username:       "alice",
			},
			event: Event{Type: "pull_request", URL: "https://github.com/otherorg/repo/pull/1"},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "otherorg",
					},
				},
				"pull_request": map[string]any{
					"user": map[string]any{
						"login": "alice",
					},
				},
			},
			userOrgs: map[string]bool{"myorg": true},
			want:     false,
		},
		{
			name: "UserEventsOnly with no org - user not a member",
			sub: Subscription{
				UserEventsOnly: true,
				Username:       "alice",
			},
			event: Event{Type: "pull_request", URL: "https://github.com/otherorg/repo/pull/1"},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "otherorg",
					},
				},
				"pull_request": map[string]any{
					"user": map[string]any{
						"login": "alice",
					},
				},
			},
			userOrgs: map[string]bool{"myorg": true},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesForTest(tt.sub, tt.event, tt.payload, tt.userOrgs)
			if got != tt.want {
				t.Errorf("matchesForTest() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMatchesPRSubscriptionEdgeCases tests edge cases in PR subscription matching.
func TestMatchesPRSubscriptionEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		sub      Subscription
		payload  map[string]any
		eventOrg string
		userOrgs map[string]bool
		want     bool
	}{
		{
			name: "no pull_request field in payload",
			sub: Subscription{
				PullRequests: []string{"https://github.com/myorg/repo/pull/123"},
			},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
			},
			eventOrg: "myorg",
			userOrgs: map[string]bool{"myorg": true},
			want:     false,
		},
		{
			name: "PR subscription with invalid PR URL",
			sub: Subscription{
				PullRequests: []string{
					"https://github.com/myorg/repo/pull/123",
					"invalid-url",
				},
			},
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
				"pull_request": map[string]any{
					"html_url": "https://github.com/myorg/repo/pull/456",
					"number":   456.0,
				},
			},
			eventOrg: "myorg",
			userOrgs: map[string]bool{"myorg": true},
			want:     false, // Doesn't match because PR number is different
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesPRSubscription(tt.sub, tt.payload, tt.eventOrg, tt.userOrgs)
			if got != tt.want {
				t.Errorf("matchesPRSubscription() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCheckCommentMentionEdgeCases tests edge cases in comment mention checking.
func TestCheckCommentMentionEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		username string
		want     bool
	}{
		{
			name:     "no mention in body",
			body:     "This is a comment without any mentions",
			username: "alice",
			want:     false,
		},
		{
			name:     "mention at end of string",
			body:     "Hello @alice",
			username: "alice",
			want:     true,
		},
		{
			name:     "mention followed by punctuation",
			body:     "Hello @alice!",
			username: "alice",
			want:     true,
		},
		{
			name:     "mention as part of longer username",
			body:     "Hello @alice123",
			username: "alice",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkCommentMention(tt.body, tt.username)
			if got != tt.want {
				t.Errorf("checkCommentMention() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestExtractEventOrg tests extracting organization from different payload structures.
func TestExtractEventOrg(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
		want    string
	}{
		{
			name: "org from repository owner",
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
			},
			want: "myorg",
		},
		{
			name: "org from organization field",
			payload: map[string]any{
				"organization": map[string]any{
					"login": "myorg",
				},
			},
			want: "myorg",
		},
		{
			name:    "no org in payload",
			payload: map[string]any{},
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEventOrg(tt.payload)
			if got != tt.want {
				t.Errorf("extractEventOrg() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMatchesUserEventsOnlyWithSpecificOrg tests UserEventsOnly with specific org.
func TestMatchesUserEventsOnlyWithSpecificOrg(t *testing.T) {
	sub := Subscription{
		Organization:   "myorg",
		UserEventsOnly: true,
		Username:       "alice",
	}

	// Event in different org - should not match
	event := Event{Type: "pull_request", URL: "https://github.com/otherorg/repo/pull/1"}
	payload := map[string]any{
		"repository": map[string]any{
			"owner": map[string]any{
				"login": "otherorg",
			},
		},
		"pull_request": map[string]any{
			"user": map[string]any{
				"login": "alice",
			},
		},
	}

	got := matchesForTest(sub, event, payload, nil)
	if got {
		t.Error("Should not match event in different org")
	}

	// Event in correct org - should match
	payload["repository"] = map[string]any{
		"owner": map[string]any{
			"login": "myorg",
		},
	}
	got = matchesForTest(sub, event, payload, nil)
	if !got {
		t.Error("Should match event in correct org")
	}
}
