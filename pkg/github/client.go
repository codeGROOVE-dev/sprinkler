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

// Client provides GitHub API functionality.
type Client struct {
	httpClient *http.Client
	token      string
}

// NewClient creates a new GitHub API client with the provided token.
func NewClient(token string) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
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

// ValidateOrgMembership checks if the authenticated user has access to the specified organization.
// Returns the authenticated user's username and nil error if successful.
func (c *Client) ValidateOrgMembership(ctx context.Context, org string) (string, error) {
	// First get the authenticated user (already has retry logic)
	user, err := c.AuthenticatedUser(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get authenticated user: %w", err)
	}

	// Sanitize org name
	org = strings.TrimSpace(org)
	if org == "" {
		return "", errors.New("organization name cannot be empty")
	}

	// Validate org name format (GitHub org names can only contain alphanumeric, hyphen, underscore)
	for _, r := range org {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return "", errors.New("invalid organization name format")
		}
	}

	var lastErr error

	// Retry org access check with exponential backoff
	err = retry.Do(
		func() error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://api.github.com/orgs/%s", org), http.NoBody)
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
			req.Header.Set("Accept", "application/vnd.github.v3+json")
			req.Header.Set("User-Agent", "webhook-sprinkler/1.0")

			resp, err := c.httpClient.Do(req)
			if err != nil {
				lastErr = fmt.Errorf("failed to make request: %w", err)
				log.Printf("GitHub API org check failed (will retry): %v", err)
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
				// Successfully accessed the org
				return nil

			case http.StatusUnauthorized:
				return retry.Unrecoverable(errors.New("invalid GitHub token"))

			case http.StatusForbidden:
				// Check if it's a rate limit issue
				if resp.Header.Get("X-RateLimit-Remaining") == "0" { //nolint:canonicalheader // GitHub API header
					resetTime := resp.Header.Get("X-RateLimit-Reset") //nolint:canonicalheader // GitHub API header
					log.Printf("GitHub API rate limit hit for org check, reset at %s", resetTime)
					lastErr = errors.New("GitHub API rate limit exceeded")
					return lastErr // Retry after backoff
				}
				// Check the specific error message
				var errResp struct {
					Message string `json:"message"`
				}
				if err := json.Unmarshal(body, &errResp); err == nil {
					if strings.Contains(errResp.Message, "Not Found") {
						return retry.Unrecoverable(errors.New("organization not found or not accessible with this token"))
					}
				}
				return retry.Unrecoverable(errors.New("access denied to organization"))

			case http.StatusNotFound:
				return retry.Unrecoverable(errors.New("organization not found or not accessible with this token"))

			case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
				// Retry on server errors
				lastErr = fmt.Errorf("GitHub API server error: %d", resp.StatusCode)
				log.Printf("GitHub API org check server error %d (will retry)", resp.StatusCode)
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
			return "", lastErr
		}
		return "", err
	}

	return user.Login, nil
}
