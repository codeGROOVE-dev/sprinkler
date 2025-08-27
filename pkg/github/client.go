// Package github provides client functionality for interacting with the GitHub API,
// including user authentication and organization validation.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	token      string
}

// NewClient creates a new GitHub API client with the provided token.
func NewClient(token string) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: clientTimeout,
		},
		token: token,
	}
}

// User represents the authenticated GitHub user.
type User struct {
	Login string `json:"login"`
}

// AuthenticatedUser returns the currently authenticated user's info.
func (c *Client) AuthenticatedUser(ctx context.Context) (*User, error) {
	var user *User
	var lastErr error

	// Retry with exponential backoff and jitter for transient failures
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
				log.Printf("GitHub API request failed (will retry): %v", err)
				return err // Retry on network errors
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					log.Printf("failed to close response body: %v", err)
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
				return retry.Unrecoverable(errors.New("invalid GitHub token"))

			case http.StatusForbidden:
				// Check if rate limited
				if resp.Header.Get("X-RateLimit-Remaining") == "0" { //nolint:canonicalheader // GitHub API header
					resetTime := resp.Header.Get("X-RateLimit-Reset") //nolint:canonicalheader // GitHub API header
					log.Printf("GitHub API rate limit hit, reset at %s", resetTime)
					lastErr = errors.New("GitHub API rate limit exceeded")
					return lastErr // Retry after backoff
				}
				return retry.Unrecoverable(errors.New("access forbidden"))

			case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
				// Retry on server errors
				lastErr = fmt.Errorf("GitHub API server error: %d", resp.StatusCode)
				log.Printf("GitHub API server error %d (will retry)", resp.StatusCode)
				return lastErr

			default:
				// Don't retry on other errors
				return retry.Unrecoverable(fmt.Errorf("unexpected status: %d", resp.StatusCode))
			}
		},
		retry.Attempts(3),
		retry.DelayType(retry.BackOffDelay),
		retry.MaxDelay(2*time.Minute),
		retry.MaxJitter(time.Second),
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

// UserAndOrgs retrieves the authenticated user's username and list of organizations.
// Returns username, list of organization names, and error.
func (c *Client) UserAndOrgs(ctx context.Context) (username string, orgs []string, err error) {
	log.Print("GitHub API: Starting authentication and fetching user organizations")

	// First get the authenticated user (already has retry logic)
	log.Print("GitHub API: Getting authenticated user info...")
	user, err := c.AuthenticatedUser(ctx)
	if err != nil {
		log.Printf("GitHub API: Failed to get authenticated user: %v", err)
		return "", nil, fmt.Errorf("failed to get authenticated user: %w", err)
	}
	log.Printf("GitHub API: Successfully authenticated as user '%s'", user.Login)

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

	log.Printf("GitHub API: User '%s' is member of %d organizations", user.Login, len(orgList))
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

	log.Print("GitHub API: Fetching user's organizations...")

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
				log.Printf("GitHub API org fetch failed (will retry): %v", err)
				return err // Retry on network errors
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					log.Printf("failed to close response body: %v", err)
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
				return retry.Unrecoverable(errors.New("invalid GitHub token"))

			case http.StatusForbidden:
				// Check if it's a rate limit issue
				if resp.Header.Get("X-Ratelimit-Remaining") == "0" {
					resetTime := resp.Header.Get("X-Ratelimit-Reset")
					log.Printf("GitHub API rate limit hit, reset at %s", resetTime)
					lastErr = errors.New("GitHub API rate limit exceeded")
					return lastErr // Retry after backoff
				}
				return retry.Unrecoverable(errors.New("access forbidden"))

			case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
				// Retry on server errors
				lastErr = fmt.Errorf("GitHub API server error: %d", resp.StatusCode)
				log.Printf("GitHub API server error %d (will retry)", resp.StatusCode)
				return lastErr

			default:
				return retry.Unrecoverable(fmt.Errorf("unexpected response status: %d", resp.StatusCode))
			}
		},
		retry.Attempts(3),
		retry.DelayType(retry.BackOffDelay),
		retry.MaxDelay(2*time.Minute),
		retry.MaxJitter(time.Second),
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
	log.Printf("GitHub API: Starting authentication and org membership validation for org '%s'", org)

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
			log.Printf("GitHub API: User '%s' is a member of organization '%s'", username, org)
			log.Printf("GitHub API: User is member of %d total organizations", len(orgNames))
			return username, orgNames, nil
		}
	}

	// User is not a member of the requested organization
	log.Printf("GitHub API: User '%s' is NOT a member of organization '%s'", username, org)
	log.Printf("GitHub API: User is member of %d organizations: %v", len(orgNames), orgNames)
	return "", nil, errors.New("user is not a member of the requested organization")
}
