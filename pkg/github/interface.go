package github

import "context"

// APIClient defines the interface for GitHub API operations.
// This allows for mocking in tests while using the real client in production.
type APIClient interface {
	// UserAndOrgs returns the authenticated user's username and organizations.
	UserAndOrgs(ctx context.Context) (username string, orgs []string, err error)

	// ValidateOrgMembership validates that the authenticated user is a member of the specified organization.
	ValidateOrgMembership(ctx context.Context, org string) (username string, orgs []string, err error)

	// UserTier fetches the user's GitHub Marketplace subscription tier.
	UserTier(ctx context.Context, username string) (Tier, error)
}

// Ensure Client implements APIClient interface.
var _ APIClient = (*Client)(nil)
