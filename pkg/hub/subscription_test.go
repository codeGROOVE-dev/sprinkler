package hub

import (
	"testing"
)

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

func TestValidateSubscription(t *testing.T) {
	tests := []struct {
		name    string
		sub     Subscription
		wantErr bool
	}{
		{
			name:    "valid username",
			sub:     Subscription{Username: "valid-user123"},
			wantErr: false,
		},
		{
			name:    "username too long",
			sub:     Subscription{Username: "this-username-is-way-too-long-for-github-limits"},
			wantErr: true,
		},
		{
			name:    "username with invalid chars",
			sub:     Subscription{Username: "user@name"},
			wantErr: true,
		},
		{
			name:    "valid PR URL",
			sub:     Subscription{PRURL: "https://github.com/owner/repo/pull/123"},
			wantErr: false,
		},
		{
			name:    "PR URL too long",
			sub:     Subscription{PRURL: "https://github.com/" + string(make([]byte, 500))},
			wantErr: true,
		},
		{
			name:    "PR URL not GitHub",
			sub:     Subscription{PRURL: "https://gitlab.com/owner/repo/pull/123"},
			wantErr: true,
		},
		{
			name:    "PR URL with path traversal",
			sub:     Subscription{PRURL: "https://github.com/../etc/passwd"},
			wantErr: true,
		},
		{
			name:    "valid repository URL",
			sub:     Subscription{Repository: "https://github.com/owner/repo"},
			wantErr: false,
		},
		{
			name:    "repository URL not GitHub",
			sub:     Subscription{Repository: "https://example.com/repo"},
			wantErr: true,
		},
		{
			name: "all valid fields",
			sub: Subscription{
				Username:   "user",
				PRURL:      "https://github.com/owner/repo/pull/1",
				Repository: "https://github.com/owner/repo",
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