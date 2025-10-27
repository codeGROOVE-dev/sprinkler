package webhook

import (
	"context"
	"testing"
)

func TestExtractPRURL(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		payload   map[string]any
		want      string
	}{
		{
			name:      "pull_request event",
			eventType: "pull_request",
			payload: map[string]any{
				"pull_request": map[string]any{
					"html_url": "https://github.com/user/repo/pull/1",
				},
			},
			want: "https://github.com/user/repo/pull/1",
		},
		{
			name:      "issue_comment on PR",
			eventType: "issue_comment",
			payload: map[string]any{
				"issue": map[string]any{
					"html_url":     "https://github.com/user/repo/pull/2",
					"pull_request": map[string]any{},
				},
			},
			want: "https://github.com/user/repo/pull/2",
		},
		{
			name:      "issue_comment on issue (not PR)",
			eventType: "issue_comment",
			payload: map[string]any{
				"issue": map[string]any{
					"html_url": "https://github.com/user/repo/issues/3",
				},
			},
			want: "",
		},
		{
			name:      "check_run with PR",
			eventType: "check_run",
			payload: map[string]any{
				"check_run": map[string]any{
					"pull_requests": []any{
						map[string]any{
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
			payload: map[string]any{
				"check_suite": map[string]any{
					"pull_requests": []any{
						map[string]any{
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
			payload:   map[string]any{},
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractPRURL(context.Background(), tt.eventType, tt.payload); got != tt.want {
				t.Errorf("ExtractPRURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
