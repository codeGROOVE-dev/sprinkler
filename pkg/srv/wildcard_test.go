package srv

import (
	"testing"
)

func TestWildcardOrganizationSubscription(t *testing.T) {
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
			name: "wildcard matches org user is member of",
			subscription: Subscription{
				Organization: "*",
				Username:     "testuser",
				EventTypes:   []string{"pull_request"},
			},
			eventOrg: "myorg",
			userOrgs: map[string]bool{
				"myorg":      true,
				"anotherorg": true,
			},
			eventType: "pull_request",
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "myorg",
					},
				},
			},
			shouldMatch: true,
		},
		{
			name: "wildcard does not match org user is not member of",
			subscription: Subscription{
				Organization: "*",
				Username:     "testuser",
				EventTypes:   []string{"pull_request"},
			},
			eventOrg: "notmyorg",
			userOrgs: map[string]bool{
				"myorg":      true,
				"anotherorg": true,
			},
			eventType: "pull_request",
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "notmyorg",
					},
				},
			},
			shouldMatch: false,
		},
		{
			name: "wildcard matches any org in user list",
			subscription: Subscription{
				Organization: "*",
				Username:     "testuser",
			},
			eventOrg: "anotherorg",
			userOrgs: map[string]bool{
				"myorg":      true,
				"anotherorg": true,
				"thirdorg":   true,
			},
			eventType: "issues",
			payload: map[string]any{
				"organization": map[string]any{
					"login": "anotherorg",
				},
			},
			shouldMatch: true,
		},
		{
			name: "wildcard with specific event type filter",
			subscription: Subscription{
				Organization: "*",
				Username:     "testuser",
				EventTypes:   []string{"issues"},
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
				},
			},
			shouldMatch: false, // Event type doesn't match
		},
		{
			name: "regular org subscription still works",
			subscription: Subscription{
				Organization: "specificorg",
				Username:     "testuser",
			},
			eventOrg: "specificorg",
			userOrgs: map[string]bool{
				"specificorg": true,
				"otherorg":    true,
			},
			eventType: "pull_request",
			payload: map[string]any{
				"repository": map[string]any{
					"owner": map[string]any{
						"login": "specificorg",
					},
				},
			},
			shouldMatch: true,
		},
		{
			name: "wildcard with user_events_only",
			subscription: Subscription{
				Organization:   "*",
				Username:       "testuser",
				UserEventsOnly: true,
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
				},
				"pull_request": map[string]any{
					"user": map[string]any{
						"login": "testuser",
					},
				},
			},
			shouldMatch: true,
		},
		{
			name: "wildcard with user_events_only - not user's event",
			subscription: Subscription{
				Organization:   "*",
				Username:       "testuser",
				UserEventsOnly: true,
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
				},
				"pull_request": map[string]any{
					"user": map[string]any{
						"login": "anotheruser",
					},
				},
			},
			shouldMatch: false,
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

func TestWildcardOrganizationValidation(t *testing.T) {
	tests := []struct {
		name    string
		sub     Subscription
		wantErr bool
	}{
		{
			name: "wildcard organization is valid",
			sub: Subscription{
				Organization: "*",
			},
			wantErr: false,
		},
		{
			name: "specific organization is valid",
			sub: Subscription{
				Organization: "myorg",
			},
			wantErr: false,
		},
		{
			name: "invalid org characters rejected",
			sub: Subscription{
				Organization: "my@org",
			},
			wantErr: true,
		},
		{
			name: "empty org is valid",
			sub: Subscription{
				Organization: "",
			},
			wantErr: false,
		},
		{
			name: "wildcard with event types is valid",
			sub: Subscription{
				Organization: "*",
				EventTypes:   []string{"pull_request", "issues"},
			},
			wantErr: false,
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
