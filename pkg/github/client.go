// Package github provides client functionality for interacting with the GitHub API,
// including user authentication and organization validation.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/retry"
)

const (
	clientTimeout = 10 * time.Second
)

// Client provides GitHub API functionality.
type Client struct {
	httpClient *http.Client
	logger     *slog.Logger
	token      string
}

// NewClient creates a new GitHub API client with the provided token.
// If logger is nil, a default discarding logger is used.
func NewClient(token string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Client{
		httpClient: &http.Client{
			Timeout: clientTimeout,
		},
		token:  token,
		logger: logger,
	}
}

// User represents the authenticated GitHub user.
type User struct {
	Login string `json:"login"`
}

// AppInstallation represents a GitHub App installation.
type AppInstallation struct {
	Account struct {
		Login string `json:"login"`
		Type  string `json:"type"` // "Organization" or "User"
	} `json:"account"`
	ID    int64 `json:"id"`
	AppID int64 `json:"app_id"`
}

// AuthenticatedUser returns the currently authenticated user's info.
func (c *Client) AuthenticatedUser(ctx context.Context) (*User, error) {
	var user *User
	var lastErr error

	// Retry with exponential backoff and full jitter for transient failures
	err := retry.Do(
		func() error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", http.NoBody)
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
			req.Header.Set("Accept", "application/vnd.github.v3+json")
			req.Header.Set("User-Agent", "webhook-sprinkler/1.0")

			resp, err := c.httpClient.Do(req)
			if err != nil {
				lastErr = fmt.Errorf("failed to make request: %w", err)
				c.logger.Warn("GitHub API request failed (will retry)", "error", err)
				return err // Retry on network errors
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					c.logger.Warn("failed to close response body", "error", err)
				}
			}()

			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
			if err != nil {
				lastErr = fmt.Errorf("failed to read response: %w", err)
				return err // Retry on read errors
			}

			// Handle status codes
			switch resp.StatusCode {
			case http.StatusOK:
				// Success - parse response
				var u User
				if err := json.Unmarshal(body, &u); err != nil {
					return retry.Unrecoverable(fmt.Errorf("failed to parse user response: %w", err))
				}
				if u.Login == "" {
					return retry.Unrecoverable(errors.New("no username found in response"))
				}
				user = &u
				return nil

			case http.StatusUnauthorized:
				// Don't retry on auth failures
				c.logger.Warn("GitHub API: 401 Unauthorized - invalid token for /user endpoint")
				return retry.Unrecoverable(errors.New("invalid GitHub token"))

			case http.StatusForbidden:
				// Check if rate limited
				if resp.Header.Get("X-RateLimit-Remaining") == "0" { //nolint:canonicalheader // GitHub API header
					resetTime := resp.Header.Get("X-RateLimit-Reset") //nolint:canonicalheader // GitHub API header
					c.logger.Warn("GitHub API: 403 Forbidden - rate limit exceeded for /user endpoint", "reset_at", resetTime)
					lastErr = errors.New("GitHub API rate limit exceeded")
					return lastErr // Retry after backoff
				}
				c.logger.Warn("GitHub API: 403 Forbidden - access denied for /user endpoint")
				return retry.Unrecoverable(errors.New("access forbidden"))

			case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
				// Retry on server errors
				lastErr = fmt.Errorf("GitHub API server error: %d", resp.StatusCode)
				c.logger.Warn("GitHub API server error (will retry)", "status", resp.StatusCode)
				return lastErr

			default:
				// Don't retry on other errors
				return retry.Unrecoverable(fmt.Errorf("unexpected status: %d", resp.StatusCode))
			}
		},
		retry.Attempts(3),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.MaxDelay(2*time.Minute),
		retry.Context(ctx),
	)
	if err != nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, err
	}

	return user, nil
}

// AppInstallationInfo retrieves information about the GitHub App installation.
// For installation tokens, we need to use /installation/repositories to get context.
func (c *Client) AppInstallationInfo(ctx context.Context) (*AppInstallation, error) {
	var installation *AppInstallation
	var lastErr error

	// Use retry for transient failures
	err := retry.Do(
		func() error {
			// Try /installation/repositories which works with installation tokens
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/installation/repositories", http.NoBody)
			if err != nil {
				return retry.Unrecoverable(fmt.Errorf("failed to create request: %w", err))
			}

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
			req.Header.Set("Accept", "application/vnd.github.v3+json")
			req.Header.Set("User-Agent", "webhook-sprinkler/1.0")

			resp, err := c.httpClient.Do(req)
			if err != nil {
				lastErr = fmt.Errorf("failed to make request: %w", err)
				c.logger.Warn("GitHub API: /installation/repositories request failed (will retry)", "error", err)
				return err // Retry on network errors
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					c.logger.Warn("failed to close response body", "error", err)
				}
			}()

			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
			if err != nil {
				lastErr = fmt.Errorf("failed to read response: %w", err)
				return err // Retry on read errors
			}

			// Log the response for debugging
			if resp.StatusCode != http.StatusOK {
				// Log first 200 chars of response body for debugging
				bodySnippet := string(body)
				if len(bodySnippet) > 200 {
					bodySnippet = bodySnippet[:200] + "..."
				}
				c.logger.Debug("GitHub API: /installation/repositories returned non-OK",
					"status", resp.StatusCode, "body", bodySnippet)
			}

			// Handle status codes
			switch resp.StatusCode {
			case http.StatusOK:
				// Success - parse response from /installation/repositories
				// This endpoint returns repositories, but we can extract org info from them
				var repoResponse struct {
					Repositories []struct {
						Owner struct {
							Login string `json:"login"`
							Type  string `json:"type"`
						} `json:"owner"`
					} `json:"repositories"`
				}
				if err := json.Unmarshal(body, &repoResponse); err != nil {
					return retry.Unrecoverable(fmt.Errorf("failed to parse installation repositories response: %w", err))
				}

				// Extract organization from repositories
				if len(repoResponse.Repositories) > 0 {
					owner := repoResponse.Repositories[0].Owner
					installation = &AppInstallation{
						Account: struct {
							Login string `json:"login"`
							Type  string `json:"type"`
						}{
							Login: owner.Login,
							Type:  owner.Type,
						},
						// We don't have the actual app ID from this endpoint, use a marker value
						ID:    0,
						AppID: 0,
					}
					return nil
				}
				// No repositories accessible - might be a new installation
				return retry.Unrecoverable(errors.New("no repositories accessible to this installation token"))

			case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
				// Don't retry on auth/not found errors - not an app token
				return retry.Unrecoverable(fmt.Errorf("not an app installation token: status %d", resp.StatusCode))

			case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
				// Retry on server errors
				lastErr = fmt.Errorf("GitHub API server error: %d", resp.StatusCode)
				c.logger.Warn("GitHub API: /installation server error (will retry)", "status", resp.StatusCode)
				return lastErr

			default:
				// Don't retry on other errors
				return retry.Unrecoverable(fmt.Errorf("unexpected status: %d", resp.StatusCode))
			}
		},
		retry.Attempts(3),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.MaxDelay(2*time.Minute),
		retry.Context(ctx),
	)
	if err != nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, err
	}

	c.logger.Info("GitHub API: App installation detected",
		"account", installation.Account.Login, "type", installation.Account.Type)
	return installation, nil
}

// UserAndOrgs retrieves the authenticated user's username and list of organizations.
// For GitHub App tokens, it returns the app's installation org.
// Returns username, list of organization names, and error.
func (c *Client) UserAndOrgs(ctx context.Context) (username string, orgs []string, err error) {
	// Detect token type for better debugging
	const legacyTokenLength = 40
	var tokenType string
	switch {
	case strings.HasPrefix(c.token, "ghp_"):
		tokenType = "personal_access_token"
	case strings.HasPrefix(c.token, "gho_"):
		tokenType = "oauth_token" // #nosec G101 - not a credential, just a type identifier
	case strings.HasPrefix(c.token, "ghs_"):
		tokenType = "server_to_server" // #nosec G101 - not a credential, just a type identifier
	case len(c.token) == legacyTokenLength:
		tokenType = "legacy_token"
	default:
		tokenType = "unknown"
	}

	c.logger.Info("GitHub API: Starting authentication", "token_type", tokenType)

	// First, try to detect if this is a GitHub App token by checking for /installation/repositories endpoint
	// Try for all tokens, not just ghs_ prefix - let the API tell us what it is
	c.logger.Debug("GitHub API: Checking if token works with /installation/repositories endpoint...")
	installation, appErr := c.AppInstallationInfo(ctx)
	if appErr == nil {
		// This is a GitHub App - return the org it's installed in
		if installation.Account.Type == "Organization" {
			c.logger.Info("GitHub API: App installation token authenticated for organization", "org", installation.Account.Login)
			return "app[installation]", []string{installation.Account.Login}, nil
		}
		// App installed on user account - treat the personal account as an "org" for subscription purposes
		c.logger.Info("GitHub API: App installation token authenticated for user account", "account", installation.Account.Login)
		return "app[installation]", []string{installation.Account.Login}, nil
	}
	c.logger.Debug("GitHub API: Token did not work with /installation/repositories, trying /user endpoint...", "error", appErr)

	// Fall back to user authentication
	c.logger.Debug("GitHub API: Getting authenticated user info...")
	user, err := c.AuthenticatedUser(ctx)
	if err != nil {
		c.logger.Warn("GitHub API: Failed to get authenticated user", "error", err)
		return "", nil, fmt.Errorf("failed to get authenticated user: %w", err)
	}
	c.logger.Info("GitHub API: Successfully authenticated as user", "user", user.Login)

	// Get user's organizations
	orgList, err := c.userOrganizations(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get user organizations: %w", err)
	}

	// Build list of org names
	orgNames := make([]string, len(orgList))
	for i, o := range orgList {
		orgNames[i] = o.Login
	}

	c.logger.Info("GitHub API: User organizations loaded", "user", user.Login, "org_count", len(orgList))
	return user.Login, orgNames, nil
}

// Organization struct to match GitHub API response.
type Organization struct {
	Login string `json:"login"`
}

// userOrganizations fetches all organizations the authenticated user is a member of.
func (c *Client) userOrganizations(ctx context.Context) ([]Organization, error) {
	var orgs []Organization
	var lastErr error

	c.logger.Debug("GitHub API: Fetching user's organizations...")

	// Retry org membership check with exponential backoff
	err := retry.Do(
		func() error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/orgs", http.NoBody)
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
			req.Header.Set("Accept", "application/vnd.github.v3+json")
			req.Header.Set("User-Agent", "webhook-sprinkler/1.0")

			resp, err := c.httpClient.Do(req)
			if err != nil {
				lastErr = fmt.Errorf("failed to make request: %w", err)
				c.logger.Warn("GitHub API org fetch failed (will retry)", "error", err)
				return err // Retry on network errors
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					c.logger.Warn("failed to close response body", "error", err)
				}
			}()

			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
			if err != nil {
				lastErr = fmt.Errorf("failed to read response: %w", err)
				return err // Retry on read errors
			}

			switch resp.StatusCode {
			case http.StatusOK:
				// Successfully got user's organizations
				if err := json.Unmarshal(body, &orgs); err != nil {
					return retry.Unrecoverable(fmt.Errorf("failed to parse organizations response: %w", err))
				}
				return nil

			case http.StatusUnauthorized:
				c.logger.Warn("GitHub API: 401 Unauthorized - invalid token for /user/orgs endpoint")
				return retry.Unrecoverable(errors.New("invalid GitHub token"))

			case http.StatusForbidden:
				// Check if it's a rate limit issue
				if resp.Header.Get("X-Ratelimit-Remaining") == "0" {
					resetTime := resp.Header.Get("X-Ratelimit-Reset")
					c.logger.Warn("GitHub API: 403 Forbidden - rate limit exceeded for /user/orgs endpoint", "reset_at", resetTime)
					lastErr = errors.New("GitHub API rate limit exceeded")
					return lastErr // Retry after backoff
				}
				c.logger.Warn("GitHub API: 403 Forbidden - access denied for /user/orgs endpoint")
				return retry.Unrecoverable(errors.New("access forbidden"))

			case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
				// Retry on server errors
				lastErr = fmt.Errorf("GitHub API server error: %d", resp.StatusCode)
				c.logger.Warn("GitHub API server error (will retry)", "status", resp.StatusCode)
				return lastErr

			default:
				return retry.Unrecoverable(fmt.Errorf("unexpected response status: %d", resp.StatusCode))
			}
		},
		retry.Attempts(3),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.MaxDelay(2*time.Minute),
		retry.Context(ctx),
	)
	if err != nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, err
	}

	return orgs, nil
}

// ValidateOrgMembership checks if the authenticated user has access to the specified organization.
// Returns the authenticated user's username, list of all their organizations, and nil error if successful.
func (c *Client) ValidateOrgMembership(ctx context.Context, org string) (username string, orgs []string, err error) {
	c.logger.Debug("GitHub API: Starting authentication and org membership validation", "org", org)

	// Sanitize org name
	org = strings.TrimSpace(org)
	if org == "" {
		return "", nil, errors.New("organization name cannot be empty")
	}

	// Validate org name format (GitHub org names can only contain alphanumeric, hyphen, underscore)
	for _, r := range org {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return "", nil, errors.New("invalid organization name format")
		}
	}

	// Get user and all their organizations
	username, orgNames, err := c.UserAndOrgs(ctx)
	if err != nil {
		return "", nil, err
	}

	// Check if the requested organization is in the user's membership list
	for _, userOrg := range orgNames {
		if strings.EqualFold(userOrg, org) {
			c.logger.Info("GitHub API: User is a member of organization", "user", username, "org", org, "total_orgs", len(orgNames))
			return username, orgNames, nil
		}
	}

	// User is not a member of the requested organization
	c.logger.Warn("GitHub API: User is NOT a member of organization", "user", username, "org", org, "member_orgs", orgNames)
	return username, orgNames, errors.New("user is not a member of the requested organization")
}

// FindPRsForCommit finds all pull requests associated with a specific commit SHA.
// This is useful for resolving check_run/check_suite events when GitHub's pull_requests array is empty.
// Returns a list of PR numbers that contain this commit.
//
// IMPORTANT: Due to race conditions in GitHub's indexing, this may initially return an empty array
// even for commits that ARE on PR branches. We implement retry logic to handle this:
// - First empty result: retry immediately after 500ms.
// - Second empty result: return empty (caller should use TTL cache).
func (c *Client) FindPRsForCommit(ctx context.Context, owner, repo, commitSHA string) ([]int, error) {
	var prNumbers []int
	var lastErr error
	attemptNum := 0

	// Use GitHub's API to list PRs associated with a commit
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s/pulls", owner, repo, commitSHA)

	c.logger.Debug("GitHub API: Looking up PRs for commit", "commit", commitSHA[:8], "owner", owner, "repo", repo)

	err := retry.Do(
		func() error {
			attemptNum++
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
			req.Header.Set("Accept", "application/vnd.github.v3+json")
			req.Header.Set("User-Agent", "webhook-sprinkler/1.0")

			c.logger.Debug("GitHub API: GET", "url", url, "attempt", attemptNum)
			resp, err := c.httpClient.Do(req)
			if err != nil {
				lastErr = fmt.Errorf("failed to make request: %w", err)
				c.logger.Warn("GitHub API request failed (will retry)", "error", err)
				return err // Retry on network errors
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					c.logger.Warn("failed to close response body", "error", err)
				}
			}()

			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
			if err != nil {
				lastErr = fmt.Errorf("failed to read response: %w", err)
				return err // Retry on read errors
			}

			// Handle status codes
			switch resp.StatusCode {
			case http.StatusOK:
				// Success - parse response
				var prs []struct {
					State  string `json:"state"`
					Number int    `json:"number"`
				}
				if err := json.Unmarshal(body, &prs); err != nil {
					return retry.Unrecoverable(fmt.Errorf("failed to parse PR list response: %w", err))
				}

				prNumbers = make([]int, len(prs))
				for i, pr := range prs {
					prNumbers[i] = pr.Number
				}

				// Handle empty results with progressive backoff
				// GitHub's indexing can take a moment after PR events
				if len(prNumbers) == 0 {
					switch attemptNum {
					case 1:
						c.logger.Info("GitHub API: Empty result on attempt 1 - retrying after 500ms", "commit", commitSHA[:8])
						time.Sleep(500 * time.Millisecond)
						return errors.New("empty result, retrying")
					case 2:
						c.logger.Info("GitHub API: Empty result on attempt 2 - retrying after 1s", "commit", commitSHA[:8])
						time.Sleep(1 * time.Second)
						return errors.New("empty result, retrying")
					default:
						c.logger.Info("GitHub API: Empty result after retries - may be push to main or PR not yet indexed",
							"commit", commitSHA[:8], "attempts", attemptNum)
					}
				} else {
					c.logger.Info("GitHub API: Found PRs for commit", "count", len(prNumbers), "commit", commitSHA[:8], "prs", prNumbers)
				}
				return nil

			case http.StatusNotFound:
				// Commit not found - could be a commit to main or repo doesn't exist
				c.logger.Debug("GitHub API: Commit not found (404) - may not exist or indexing delayed", "commit", commitSHA[:8])
				return retry.Unrecoverable(fmt.Errorf("commit not found: %s", commitSHA))

			case http.StatusUnauthorized, http.StatusForbidden:
				// Don't retry on auth errors
				c.logger.Warn("GitHub API: Auth failed for commit", "status", resp.StatusCode, "commit", commitSHA[:8])
				return retry.Unrecoverable(fmt.Errorf("authentication failed: status %d", resp.StatusCode))

			case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
				// Retry on server errors
				lastErr = fmt.Errorf("GitHub API server error: %d", resp.StatusCode)
				c.logger.Warn("GitHub API: Server error for commit (will retry)", "status", resp.StatusCode, "commit", commitSHA[:8])
				return lastErr

			default:
				// Don't retry on other errors
				c.logger.Warn("GitHub API: Unexpected status for commit", "status", resp.StatusCode, "commit", commitSHA[:8], "body", string(body))
				return retry.Unrecoverable(fmt.Errorf("unexpected status: %d, body: %s", resp.StatusCode, string(body)))
			}
		},
		retry.Attempts(4),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.MaxDelay(2*time.Minute),
		retry.Context(ctx),
	)
	if err != nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, err
	}

	return prNumbers, nil
}
