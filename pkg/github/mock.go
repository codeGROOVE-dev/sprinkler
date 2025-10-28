package github

import (
	"context"
	"errors"
)

// MockClient is a mock GitHub API client for testing.
type MockClient struct {
	Err                        error
	Username                   string
	LastValidatedOrg           string
	Orgs                       []string
	UserAndOrgsCalls           int
	ValidateOrgMembershipCalls int
}

// UserAndOrgs returns the mock user info.
func (m *MockClient) UserAndOrgs(ctx context.Context) (username string, orgs []string, err error) {
	m.UserAndOrgsCalls++
	if m.Err != nil {
		return "", nil, m.Err
	}
	return m.Username, m.Orgs, nil
}

// ValidateOrgMembership validates organization membership using the mock data.
func (m *MockClient) ValidateOrgMembership(ctx context.Context, org string) (username string, orgs []string, err error) {
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

// Ensure MockClient implements APIClient interface.
var _ APIClient = (*MockClient)(nil)
