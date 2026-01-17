// Package security provides security utilities for the webhook sprinkler,
// including client IP extraction and User-Agent validation.
package security

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// ClientIP extracts the client IP from the request.
// We only use RemoteAddr to avoid header spoofing.
func ClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If split fails, RemoteAddr might be just an IP without port
		return r.RemoteAddr
	}
	return ip
}

// UserAgent represents a parsed client User-Agent header.
type UserAgent struct {
	Raw     string
	Name    string
	Version string
}

var (
	// ErrMissingUserAgent is returned when the User-Agent header is missing or empty.
	ErrMissingUserAgent = errors.New("User-Agent header is required")

	// ErrInvalidUserAgent is returned when the User-Agent header doesn't match the required format.
	ErrInvalidUserAgent = errors.New("User-Agent must be in format: client-name/version (e.g., slacker/v1.0.0)")

	// userAgentPattern validates User-Agent format: client-name/version.
	// Client name: alphanumeric, hyphens, underscores (1-64 chars).
	// Version: any non-whitespace characters (1-32 chars).
	userAgentPattern = regexp.MustCompile(`^([a-zA-Z0-9_-]{1,64})/(\S{1,32})$`)
)

// ParseUserAgent extracts and validates the User-Agent header from an HTTP request.
// It returns a UserAgent struct containing the parsed name and version, or an error
// if the header is missing or doesn't match the required format: client-name/version.
func ParseUserAgent(r *http.Request) (*UserAgent, error) {
	raw := r.UserAgent()
	if raw == "" {
		return nil, ErrMissingUserAgent
	}

	// Extract only the first component before any whitespace or additional details
	// This handles cases like "slacker/v1.0.0 (linux; amd64)" -> "slacker/v1.0.0"
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return nil, ErrMissingUserAgent
	}
	first := fields[0]

	matches := userAgentPattern.FindStringSubmatch(first)
	if matches == nil {
		return nil, fmt.Errorf("%w: got %q", ErrInvalidUserAgent, raw)
	}

	return &UserAgent{
		Raw:     raw,
		Name:    matches[1],
		Version: matches[2],
	}, nil
}
