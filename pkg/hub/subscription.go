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
type Subscription struct {
	Organization string   `json:"organization"`
	Username     string   `json:"-"`
	EventTypes   []string `json:"event_types,omitempty"`
	MyEventsOnly bool     `json:"my_events_only,omitempty"`
}

// Validate performs security validation on subscription data.
func (s *Subscription) Validate() error {
	// Validate organization
	if s.Organization == "" {
		return errors.New("organization is required")
	}
	if len(s.Organization) > 39 { // GitHub org name max length
		return errors.New("invalid organization name")
	}
	// GitHub org names can only contain alphanumeric characters, hyphens, and underscores
	for _, c := range s.Organization {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return errors.New("invalid organization name format")
		}
	}

	// Validate event types if specified
	if len(s.EventTypes) > 50 { // Reasonable limit for number of event types
		return errors.New("too many event types specified")
	}
	for _, eventType := range s.EventTypes {
		if len(eventType) > 50 || eventType == "" {
			return errors.New("invalid event type")
		}
		// GitHub event types typically use underscores and lowercase
		for _, c := range eventType {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
				return errors.New("invalid event type format")
			}
		}
	}

	return nil
}

// matches determines if an event matches a client's subscription.
func matches(sub Subscription, event Event, payload map[string]interface{}) bool {
	// If no organization specified, match nothing
	if sub.Organization == "" {
		return false
	}

	// Check if event type matches subscription
	if len(sub.EventTypes) > 0 {
		eventTypeMatches := false
		for _, allowedType := range sub.EventTypes {
			if event.Type == allowedType {
				eventTypeMatches = true
				break
			}
		}
		if !eventTypeMatches {
			return false
		}
	}

	// First check if the event is from the subscribed organization
	orgMatches := false

	// Check repository owner
	if repo, ok := payload["repository"].(map[string]interface{}); ok {
		if owner, ok := repo["owner"].(map[string]interface{}); ok {
			if login, ok := owner["login"].(string); ok {
				// Case-insensitive org name comparison
				if strings.EqualFold(login, sub.Organization) {
					orgMatches = true
				}
			}
		}
	}

	// Also check organization field directly (some events include it)
	if !orgMatches {
		if org, ok := payload["organization"].(map[string]interface{}); ok {
			if login, ok := org["login"].(string); ok {
				if strings.EqualFold(login, sub.Organization) {
					orgMatches = true
				}
			}
		}
	}

	if !orgMatches {
		return false
	}

	// If MyEventsOnly is false, match all org events
	if !sub.MyEventsOnly {
		return true
	}

	// Otherwise, check if the authenticated user is involved
	// Username is populated during authentication
	return matchesUser(sub.Username, payload)
}

// matchesUser checks if a username matches any relevant field in the payload.
// extractLogin extracts the login from a user object.
func extractLogin(user map[string]interface{}) (string, bool) {
	login, ok := user["login"].(string)
	return login, ok
}

// matchesUserInObject checks if username matches login in a user object.
func matchesUserInObject(user map[string]interface{}, username string) bool {
	if login, ok := extractLogin(user); ok && strings.EqualFold(login, username) {
		return true
	}
	return false
}

// matchesUserInList checks if username matches any login in a list of user objects.
func matchesUserInList(users []interface{}, username string) bool {
	for _, item := range users {
		if user, ok := item.(map[string]interface{}); ok {
			if matchesUserInObject(user, username) {
				return true
			}
		}
	}
	return false
}

// checkPullRequestUsers checks PR author, assignees, and reviewers.
func checkPullRequestUsers(pr map[string]interface{}, username string) bool {
	// Check PR author
	if user, ok := pr["user"].(map[string]interface{}); ok {
		if matchesUserInObject(user, username) {
			return true
		}
	}

	// Check assignees
	if assignees, ok := pr["assignees"].([]interface{}); ok {
		if matchesUserInList(assignees, username) {
			return true
		}
	}

	// Check requested reviewers
	if reviewers, ok := pr["requested_reviewers"].([]interface{}); ok {
		if matchesUserInList(reviewers, username) {
			return true
		}
	}

	return false
}

// checkCommentMention checks if username is mentioned in comment body.
func checkCommentMention(body, username string) bool {
	// Check for exact @username match (case-insensitive)
	bodyLower := strings.ToLower(body)
	mentionPrefix := "@" + strings.ToLower(username)
	idx := strings.Index(bodyLower, mentionPrefix)
	if idx < 0 {
		return false
	}

	// Check that it's not part of a longer username
	nextIdx := idx + len(mentionPrefix)
	if nextIdx >= len(bodyLower) {
		return true
	}

	nextChar := bodyLower[nextIdx]
	return !((nextChar >= 'a' && nextChar <= 'z') || (nextChar >= '0' && nextChar <= '9') || nextChar == '-')
}

func matchesUser(username string, payload map[string]interface{}) bool {
	// Check PR author, assignees, and reviewers
	if pr, ok := payload["pull_request"].(map[string]interface{}); ok {
		if checkPullRequestUsers(pr, username) {
			return true
		}
	}

	// Check review author
	if review, ok := payload["review"].(map[string]interface{}); ok {
		if user, ok := review["user"].(map[string]interface{}); ok {
			if matchesUserInObject(user, username) {
				return true
			}
		}
	}

	// Check comment author and mentions
	if comment, ok := payload["comment"].(map[string]interface{}); ok {
		if user, ok := comment["user"].(map[string]interface{}); ok {
			if matchesUserInObject(user, username) {
				return true
			}
		}

		// Check mentions in comment body
		if body, ok := comment["body"].(string); ok {
			if checkCommentMention(body, username) {
				return true
			}
		}
	}

	// Check sender (action performer)
	if sender, ok := payload["sender"].(map[string]interface{}); ok {
		if matchesUserInObject(sender, username) {
			return true
		}
	}

	return false
}
