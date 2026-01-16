package github

import (
	"context"
	"errors"
	"sync"
)

// MockClient is a mock GitHub API client for testing.
// Thread-safe for concurrent access.
//
//nolint:govet // fieldalignment: minimal impact, current order is logical
type MockClient struct {
	Orgs                       []string
	Err                        error
	Username                   string
	LastValidatedOrg           string
	Tier                       Tier // Mock tier to return
	mu                         sync.Mutex
	UserAndOrgsCalls           int
	ValidateOrgMembershipCalls int
	UserTierCalls              int
}

// UserAndOrgs returns the mock user info.
func (m *MockClient) UserAndOrgs(_ context.Context) (username string, orgs []string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.UserAndOrgsCalls++
	if m.Err != nil {
		return "", nil, m.Err
	}
	return m.Username, m.Orgs, nil
}

// ValidateOrgMembership validates organization membership using the mock data.
func (m *MockClient) ValidateOrgMembership(_ context.Context, org string) (username string, orgs []string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ValidateOrgMembershipCalls++
	m.LastValidatedOrg = org

	if m.Err != nil {
		return "", nil, m.Err
	}

	// Check if user is member of the requested org
	isMember := false
	for _, userOrg := range m.Orgs {
		if userOrg == org {
			isMember = true
			break
		}
	}

	if !isMember {
		// Return username and orgs even on error so caller can show what orgs user IS in
		return m.Username, m.Orgs, errors.New("not a member of organization " + org)
	}

	return m.Username, m.Orgs, nil
}

// UserTier returns the mock tier.
func (m *MockClient) UserTier(_ context.Context, _ string) (Tier, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.UserTierCalls++
	if m.Err != nil {
		return TierFree, m.Err
	}
	// If no tier is set, default to TierFree
	if m.Tier == "" {
		return TierFree, nil
	}
	return m.Tier, nil
}

// Ensure MockClient implements APIClient interface.
var _ APIClient = (*MockClient)(nil)
