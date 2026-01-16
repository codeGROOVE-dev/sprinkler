package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Tier represents a GitHub Marketplace pricing tier.
type Tier string

const (
	// TierFree is the default tier for users without a paid subscription.
	TierFree Tier = "free"
	// TierPro is the Pro tier for individual users.
	TierPro Tier = "pro"
	// TierFlock is the Flock tier for teams/organizations.
	TierFlock Tier = "flock"
)

// MarketplacePlan represents a GitHub Marketplace subscription plan.
type MarketplacePlan struct {
	Name string `json:"name"`
}

// MarketplaceAccount represents a GitHub Marketplace account subscription.
type MarketplaceAccount struct {
	Plan MarketplacePlan `json:"plan"`
}

// UserTier fetches the user's GitHub Marketplace subscription tier.
// Returns TierFree if no subscription exists or on API errors (graceful degradation).
func (c *Client) UserTier(ctx context.Context, username string) (Tier, error) {
	if username == "" {
		return TierFree, errors.New("username cannot be empty")
	}

	// Query GitHub Marketplace API for user's subscription
	url := fmt.Sprintf("https://api.github.com/marketplace_listing/accounts/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return TierFree, fmt.Errorf("failed to create marketplace API request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-Github-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "webhook-sprinkler/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Warn("marketplace API request failed", "error", err, "username", username)
		return TierFree, fmt.Errorf("marketplace API request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.logger.Warn("failed to close marketplace response body", "error", closeErr)
		}
	}()

	// 404 means no subscription - this is normal, not an error
	if resp.StatusCode == http.StatusNotFound {
		c.logger.Info("no marketplace subscription found", "username", username)
		return TierFree, nil
	}

	// Handle other error status codes
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<10)) // Read up to 1KB for error message
		if err != nil {
			c.logger.Warn("failed to read error response", "error", err)
		}
		c.logger.Warn("marketplace API returned error",
			"status", resp.StatusCode,
			"username", username,
			"body", string(body))
		return TierFree, fmt.Errorf("marketplace API error: status %d", resp.StatusCode)
	}

	// Parse successful response
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		c.logger.Warn("failed to read marketplace response", "error", err)
		return TierFree, fmt.Errorf("failed to read marketplace response: %w", err)
	}

	var account MarketplaceAccount
	if err := json.Unmarshal(body, &account); err != nil {
		c.logger.Warn("failed to parse marketplace response", "error", err, "body", string(body))
		return TierFree, fmt.Errorf("failed to parse marketplace response: %w", err)
	}

	// Map plan name to tier (update when marketplace listing is approved)
	var tier Tier
	switch strings.ToLower(account.Plan.Name) {
	case "pro":
		tier = TierPro
	case "flock", "team", "enterprise":
		tier = TierFlock
	default:
		tier = TierFree
	}

	c.logger.Info("marketplace tier detected",
		"username", username,
		"plan", account.Plan.Name,
		"tier", tier)

	return tier, nil
}
