package hub

import (
	"errors"
	"fmt"
	"strings"
)

const (
	maxOrgNameLength      = 39  // GitHub org name max length
	maxEventTypeCount     = 50  // Reasonable limit for number of event types
	maxEventTypeLength    = 50  // Max length of individual event type
	maxPRsPerSubscription = 200 // Maximum number of PRs to subscribe to
	maxPRURLLength        = 500 // Maximum length of a PR URL
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
	UserEventsOnly bool     `json:"user_events_only,omitempty"`
	PullRequests []string `json:"pull_requests,omitempty"` // List of PR URLs to subscribe to
}

// Validate performs security validation on subscription data.
func (s *Subscription) Validate() error {
	// Organization is optional when subscribing to specific PRs or my events only
	// The server will validate that the user has access to the resources
	if s.Organization != "" {
		// Allow wildcard to subscribe to all orgs
		if s.Organization == "*" {
			// Wildcard is valid - subscribes to all orgs the user is a member of
			return nil
		}

		if len(s.Organization) > maxOrgNameLength {
			return errors.New("invalid organization name")
		}
		// GitHub org names can only contain alphanumeric characters, hyphens, and underscores
		for _, c := range s.Organization {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return errors.New("invalid organization name format")
			}
		}
	}

	// Validate event types if specified
	if len(s.EventTypes) > maxEventTypeCount {
		return errors.New("too many event types specified")
	}
	for _, eventType := range s.EventTypes {
		if len(eventType) > maxEventTypeLength || eventType == "" {
			return errors.New("invalid event type")
		}
		// GitHub event types typically use underscores and lowercase
		for _, c := range eventType {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
				return errors.New("invalid event type format")
			}
		}
	}

	// Validate PR URLs if specified
	if len(s.PullRequests) > 0 {
		if len(s.PullRequests) > maxPRsPerSubscription {
			return errors.New("too many PR URLs specified (max 200)")
		}

		// Validate each PR URL
		for _, prURL := range s.PullRequests {
			if prURL == "" {
				return errors.New("empty PR URL")
			}

			// Limit URL length to prevent memory exhaustion
			if len(prURL) > maxPRURLLength {
				return errors.New("PR URL too long")
			}

			// Basic validation - should be a GitHub PR URL
			// Format: https://github.com/owner/repo/pull/number
			if !strings.HasPrefix(prURL, "https://github.com/") && !strings.HasPrefix(prURL, "http://github.com/") {
				return errors.New("invalid PR URL format")
			}

			// Check if it contains /pull/
			if !strings.Contains(prURL, "/pull/") {
				return errors.New("URL must be a pull request URL")
			}

			// Validate the URL can be parsed to prevent injection
			owner, repo, prNum, err := parsePRUrl(prURL)
			if err != nil {
				return errors.New("invalid PR URL structure")
			}
			if owner == "" || repo == "" || prNum <= 0 {
				return errors.New("invalid PR URL components")
			}
		}
	}

	return nil
}

// parsePRUrl extracts owner, repo, and PR number from a GitHub PR URL.
func parsePRUrl(prURL string) (owner, repo string, prNumber int, err error) {
	// Remove protocol
	url := strings.TrimPrefix(prURL, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "github.com/")

	// Split by /
	parts := strings.Split(url, "/")
	if len(parts) < 4 || parts[2] != "pull" {
		return "", "", 0, errors.New("invalid PR URL format")
	}

	owner = parts[0]
	repo = parts[1]

	// Parse PR number
	var num int
	if _, err := fmt.Sscanf(parts[3], "%d", &num); err != nil {
		return "", "", 0, errors.New("invalid PR number")
	}

	return owner, repo, num, nil
}

// matches determines if an event matches a client's subscription.
// userOrgs contains the lowercase organization names the user is a member of.
func matches(sub Subscription, event Event, payload map[string]any, userOrgs map[string]bool) bool {
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

	// Extract the organization from the event
	eventOrg := ""

	// Check repository owner
	if repo, ok := payload["repository"].(map[string]any); ok {
		if owner, ok := repo["owner"].(map[string]any); ok {
			if login, ok := owner["login"].(string); ok {
				eventOrg = login
			}
		}
	}

	// Also check organization field directly (some events include it)
	if eventOrg == "" {
		if org, ok := payload["organization"].(map[string]any); ok {
			if login, ok := org["login"].(string); ok {
				eventOrg = login
			}
		}
	}

	// Check if this is a PR subscription (no org required)
	if len(sub.PullRequests) > 0 {
		// For PR subscriptions, check if this event is about one of the subscribed PRs
		// and the user is a member of the organization

		// Only check org membership if we have an eventOrg
		if eventOrg != "" && !userOrgs[strings.ToLower(eventOrg)] {
			// User is not a member of this org, don't deliver the event
			return false
		}

		// Extract PR information from the event
		if pr, ok := payload["pull_request"].(map[string]any); ok {
			// Get PR number
			prNumber, ok := pr["number"].(float64)
			if !ok {
				return false
			}

			// Get repository info
			repoName := ""
			if repo, ok := payload["repository"].(map[string]any); ok {
				if name, ok := repo["name"].(string); ok {
					repoName = name
				}
			}

			// Check if this PR matches any of the subscribed PRs
			for _, prURL := range sub.PullRequests {
				owner, repo, num, err := parsePRUrl(prURL)
				if err != nil {
					continue
				}

				// Check if this matches the event
				if strings.EqualFold(owner, eventOrg) &&
					strings.EqualFold(repo, repoName) &&
					int(prNumber) == num {
					return true
				}
			}
		}

		// Not a PR event or not one of the subscribed PRs
		return false
	}

	// For UserEventsOnly mode (no org required if subscribing to user's events across all orgs)
	if sub.UserEventsOnly {
		// Check org constraints
		if sub.Organization != "" {
			if sub.Organization == "*" {
				// Wildcard - check if user is member of the event's org
				if eventOrg != "" && !userOrgs[strings.ToLower(eventOrg)] {
					return false
				}
			} else if !strings.EqualFold(eventOrg, sub.Organization) {
				// Specific org - must match
				return false
			}
		} else {
			// No org specified - check user is member of the event's org
			if eventOrg != "" && !userOrgs[strings.ToLower(eventOrg)] {
				return false
			}
		}
		// Check if user is involved in the event
		return matchesUser(sub.Username, payload)
	}

	// For regular subscription mode with org specified
	if sub.Organization != "" {
		// Handle wildcard organization - matches any org the user is a member of
		if sub.Organization == "*" {
			// Check if the event org is one the user is a member of
			return eventOrg != "" && userOrgs[strings.ToLower(eventOrg)]
		}
		// Case-insensitive org name comparison
		return strings.EqualFold(eventOrg, sub.Organization)
	}

	// No matching mode found
	return false
}

// matchesUserInObject checks if username matches login in a user object.
func matchesUserInObject(user map[string]any, username string) bool {
	login, ok := user["login"].(string)
	return ok && strings.EqualFold(login, username)
}

// matchesUserInList checks if username matches any login in a list of user objects.
func matchesUserInList(users []any, username string) bool {
	for _, item := range users {
		if user, ok := item.(map[string]any); ok {
			if matchesUserInObject(user, username) {
				return true
			}
		}
	}
	return false
}

// checkPullRequestUsers checks PR author, assignees, and reviewers.
func checkPullRequestUsers(pr map[string]any, username string) bool {
	// Check PR author
	if user, ok := pr["user"].(map[string]any); ok {
		if matchesUserInObject(user, username) {
			return true
		}
	}

	// Check assignees
	if assignees, ok := pr["assignees"].([]any); ok {
		if matchesUserInList(assignees, username) {
			return true
		}
	}

	// Check requested reviewers
	if reviewers, ok := pr["requested_reviewers"].([]any); ok {
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
	return (nextChar < 'a' || nextChar > 'z') && (nextChar < '0' || nextChar > '9') && nextChar != '-'
}

func matchesUser(username string, payload map[string]any) bool {
	// Check PR author, assignees, and reviewers
	if pr, ok := payload["pull_request"].(map[string]any); ok {
		if checkPullRequestUsers(pr, username) {
			return true
		}
	}

	// Check review author
	if review, ok := payload["review"].(map[string]any); ok {
		if user, ok := review["user"].(map[string]any); ok {
			if matchesUserInObject(user, username) {
				return true
			}
		}
	}

	// Check comment author and mentions
	if comment, ok := payload["comment"].(map[string]any); ok {
		if user, ok := comment["user"].(map[string]any); ok {
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
	if sender, ok := payload["sender"].(map[string]any); ok {
		if matchesUserInObject(sender, username) {
			return true
		}
	}

	return false
}
