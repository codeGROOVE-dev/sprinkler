package hub

import (
	"errors"
	"strings"
)

var (
	// ErrInvalidUsername indicates an invalid GitHub username.
	ErrInvalidUsername = errors.New("invalid username")
	// ErrInvalidURL indicates an invalid URL.
	ErrInvalidURL = errors.New("invalid URL")
)

// Subscription represents a client's subscription criteria.
// At least one field must be specified for a valid subscription.
type Subscription struct {
	Username   string `json:"username,omitempty"`   // GitHub username to watch
	PRURL      string `json:"pr_url,omitempty"`    // Specific PR URL to watch
	Repository string `json:"repository,omitempty"` // Repository URL to watch
}

// IsEmpty returns true if no subscription criteria are specified.
func (s Subscription) IsEmpty() bool {
	return s.Username == "" && s.PRURL == "" && s.Repository == ""
}

// Validate performs security validation on subscription data.
func (s *Subscription) Validate() error {
	// Validate username
	if s.Username != "" {
		if len(s.Username) > 39 { // GitHub username max length
			return ErrInvalidUsername
		}
		// GitHub usernames can only contain alphanumeric characters and hyphens
		for _, c := range s.Username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return ErrInvalidUsername
			}
		}
	}

	// Validate PR URL
	if s.PRURL != "" {
		if len(s.PRURL) > 500 || !strings.HasPrefix(s.PRURL, "https://github.com/") {
			return ErrInvalidURL
		}
		// Check for path traversal
		if strings.Contains(s.PRURL, "..") || strings.Contains(s.PRURL[19:], "//") {
			return ErrInvalidURL
		}
	}

	// Validate repository URL
	if s.Repository != "" {
		if len(s.Repository) > 500 || !strings.HasPrefix(s.Repository, "https://github.com/") {
			return ErrInvalidURL
		}
		// Check for path traversal
		if strings.Contains(s.Repository, "..") || strings.Contains(s.Repository[19:], "//") {
			return ErrInvalidURL
		}
	}

	return nil
}

// matches determines if an event matches a client's subscription.
func matches(sub Subscription, event Event, payload map[string]interface{}) bool {
	// If no filters specified, match nothing (explicit subscription required)
	if sub.IsEmpty() {
		return false
	}

	// Check PR URL match
	if sub.PRURL != "" && event.URL == sub.PRURL {
		return true
	}

	// Check repository match
	if sub.Repository != "" {
		if repo, ok := payload["repository"].(map[string]interface{}); ok {
			if htmlURL, ok := repo["html_url"].(string); ok && htmlURL == sub.Repository {
				return true
			}
		}
	}

	// Check username match (author, assignee, reviewer, mentioned)
	if sub.Username != "" {
		if matchesUser(sub.Username, payload) {
			return true
		}
	}

	return false
}

// matchesUser checks if a username matches any relevant field in the payload.
func matchesUser(username string, payload map[string]interface{}) bool {
	// Check PR author
	if pr, ok := payload["pull_request"].(map[string]interface{}); ok {
		if user, ok := pr["user"].(map[string]interface{}); ok {
			if login, ok := user["login"].(string); ok && login == username {
				return true
			}
		}

		// Check assignees
		if assignees, ok := pr["assignees"].([]interface{}); ok {
			for _, assignee := range assignees {
				if a, ok := assignee.(map[string]interface{}); ok {
					if login, ok := a["login"].(string); ok && login == username {
						return true
					}
				}
			}
		}

		// Check requested reviewers
		if reviewers, ok := pr["requested_reviewers"].([]interface{}); ok {
			for _, reviewer := range reviewers {
				if r, ok := reviewer.(map[string]interface{}); ok {
					if login, ok := r["login"].(string); ok && login == username {
						return true
					}
				}
			}
		}
	}

	// Check review author
	if review, ok := payload["review"].(map[string]interface{}); ok {
		if user, ok := review["user"].(map[string]interface{}); ok {
			if login, ok := user["login"].(string); ok && login == username {
				return true
			}
		}
	}

	// Check comment author
	if comment, ok := payload["comment"].(map[string]interface{}); ok {
		if user, ok := comment["user"].(map[string]interface{}); ok {
			if login, ok := user["login"].(string); ok && login == username {
				return true
			}
		}

		// Check mentions in comment body
		if body, ok := comment["body"].(string); ok {
			// Check for exact @username match (not partial)
			mentionPrefix := "@" + username
			if idx := strings.Index(body, mentionPrefix); idx >= 0 {
				// Check that it's not part of a longer username
				nextIdx := idx + len(mentionPrefix)
				if nextIdx >= len(body) {
					return true
				}
				nextChar := body[nextIdx]
				if !((nextChar >= 'a' && nextChar <= 'z') || (nextChar >= 'A' && nextChar <= 'Z') || (nextChar >= '0' && nextChar <= '9') || nextChar == '-') {
					return true
				}
			}
		}
	}

	// Check sender (action performer)
	if sender, ok := payload["sender"].(map[string]interface{}); ok {
		if login, ok := sender["login"].(string); ok && login == username {
			return true
		}
	}

	return false
}