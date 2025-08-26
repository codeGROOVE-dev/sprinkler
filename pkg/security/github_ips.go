package security

import (
	"net"
)

// GitHub webhook IP ranges (from https://api.github.com/meta)
// These should be updated periodically.
var githubWebhookCIDRs = []string{
	"192.30.252.0/22",
	"185.199.108.0/22",
	"140.82.112.0/20",
	"143.55.64.0/20",
	"2a0a:a440::/29",
	"2606:50c0::/32",
}

// GitHubIPValidator validates if an IP is from GitHub.
type GitHubIPValidator struct {
	networks []*net.IPNet
	enabled  bool
}

// NewGitHubIPValidator creates a new GitHub IP validator.
func NewGitHubIPValidator(enabled bool) (*GitHubIPValidator, error) {
	validator := &GitHubIPValidator{
		enabled: enabled,
	}

	if !enabled {
		return validator, nil
	}

	// Parse CIDR blocks
	for _, cidr := range githubWebhookCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		validator.networks = append(validator.networks, network)
	}

	return validator, nil
}

// IsValid checks if an IP is from GitHub.
func (v *GitHubIPValidator) IsValid(ipStr string) bool {
	if !v.enabled {
		return true // Allow all IPs if validation is disabled
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check if IP is in any of the GitHub ranges
	for _, network := range v.networks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
