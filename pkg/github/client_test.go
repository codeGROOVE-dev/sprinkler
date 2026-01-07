package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestNewClient tests the client constructor.
func TestNewClient(t *testing.T) {
	t.Parallel()

	token := "ghp_test123"
	client := NewClient(token, nil)

	if client == nil {
		t.Fatal("NewClient returned nil")
	}
	if client.token != token {
		t.Errorf("token = %q, want %q", client.token, token)
	}
	if client.httpClient == nil {
		t.Error("httpClient is nil")
	}
	if client.httpClient.Timeout != clientTimeout {
		t.Errorf("timeout = %v, want %v", client.httpClient.Timeout, clientTimeout)
	}
}

// TestAuthenticatedUser_Success tests successful user authentication.
func TestAuthenticatedUser_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Accept") != "application/vnd.github.v3+json" {
			t.Errorf("unexpected accept header: %s", r.Header.Get("Accept"))
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	// Override the base URL by creating a custom request
	originalURL := "https://api.github.com/user"
	client.httpClient.Transport = &redirectTransport{
		from: originalURL,
		to:   server.URL + "/user",
	}

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("AuthenticatedUser failed: %v", err)
	}
	if user.Login != "testuser" {
		t.Errorf("username = %q, want %q", user.Login, "testuser")
	}
}

// TestAuthenticatedUser_Unauthorized tests 401 response.
func TestAuthenticatedUser_Unauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer server.Close()

	client := NewClient("invalid-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user",
		to:   server.URL + "/user",
	}

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for unauthorized, got nil")
	}
	if !strings.Contains(err.Error(), "invalid GitHub token") {
		t.Errorf("unexpected error: %v", err)
	}
	if user != nil {
		t.Errorf("expected nil user, got %+v", user)
	}
}

// TestAuthenticatedUser_RateLimit tests 403 rate limit response.
func TestAuthenticatedUser_RateLimit(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("X-RateLimit-Remaining", "0")      //nolint:canonicalheader // GitHub API header
		w.Header().Set("X-RateLimit-Reset", "1234567890") //nolint:canonicalheader // GitHub API header
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user",
		to:   server.URL + "/user",
	}

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for rate limit, got nil")
	}
	if !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Errorf("unexpected error: %v", err)
	}
	// Should retry 3 times
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// TestAuthenticatedUser_ServerError tests 500 response with retry.
func TestAuthenticatedUser_ServerError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Succeed on third attempt
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user",
		to:   server.URL + "/user",
	}

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("expected success after retries, got error: %v", err)
	}
	if user.Login != "testuser" {
		t.Errorf("username = %q, want %q", user.Login, "testuser")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

// TestAuthenticatedUser_EmptyUsername tests response with empty username.
func TestAuthenticatedUser_EmptyUsername(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: ""})
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user",
		to:   server.URL + "/user",
	}

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for empty username, got nil")
	}
	if !strings.Contains(err.Error(), "no username found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAppInstallationInfo_Success tests successful app installation info retrieval.
func TestAppInstallationInfo_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/installation/repositories" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"repositories": []map[string]interface{}{
				{
					"owner": map[string]interface{}{
						"login": "testorg",
						"type":  "Organization",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient("ghs_test-app-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/installation/repositories",
		to:   server.URL + "/installation/repositories",
	}

	ctx := context.Background()
	info, err := client.AppInstallationInfo(ctx)
	if err != nil {
		t.Fatalf("AppInstallationInfo failed: %v", err)
	}
	if info.Account.Login != "testorg" {
		t.Errorf("account login = %q, want %q", info.Account.Login, "testorg")
	}
	if info.Account.Type != "Organization" {
		t.Errorf("account type = %q, want %q", info.Account.Type, "Organization")
	}
}

// TestAppInstallationInfo_NotAnAppToken tests non-app token.
func TestAppInstallationInfo_NotAnAppToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer server.Close()

	client := NewClient("ghp_user-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/installation/repositories",
		to:   server.URL + "/installation/repositories",
	}

	ctx := context.Background()
	_, err := client.AppInstallationInfo(ctx)
	if err == nil {
		t.Fatal("expected error for non-app token, got nil")
	}
	if !strings.Contains(err.Error(), "not an app installation token") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAppInstallationInfo_NoRepositories tests app with no accessible repositories.
func TestAppInstallationInfo_NoRepositories(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"repositories": []map[string]interface{}{},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient("ghs_test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/installation/repositories",
		to:   server.URL + "/installation/repositories",
	}

	ctx := context.Background()
	_, err := client.AppInstallationInfo(ctx)
	if err == nil {
		t.Fatal("expected error for no repositories, got nil")
	}
	if !strings.Contains(err.Error(), "no repositories accessible") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserAndOrgs_AppToken tests UserAndOrgs with a GitHub App token.
func TestUserAndOrgs_AppToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/installation/repositories" {
			w.WriteHeader(http.StatusOK)
			response := map[string]interface{}{
				"repositories": []map[string]interface{}{
					{
						"owner": map[string]interface{}{
							"login": "testorg",
							"type":  "Organization",
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(response)
		} else {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient("ghs_app-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/installation/repositories",
		to:   server.URL + "/installation/repositories",
	}

	ctx := context.Background()
	username, orgs, err := client.UserAndOrgs(ctx)
	if err != nil {
		t.Fatalf("UserAndOrgs failed: %v", err)
	}
	if username != "app[installation]" {
		t.Errorf("username = %q, want %q", username, "app[installation]")
	}
	if len(orgs) != 1 || orgs[0] != "testorg" {
		t.Errorf("orgs = %v, want [testorg]", orgs)
	}
}

// TestUserAndOrgs_UserToken tests UserAndOrgs with a user token.
func TestUserAndOrgs_UserToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/installation/repositories":
			w.WriteHeader(http.StatusNotFound)
		case "/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
		case "/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Login: "org1"},
				{Login: "org2"},
			}
			_ = json.NewEncoder(w).Encode(orgs)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient("ghp_user-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	username, orgs, err := client.UserAndOrgs(ctx)
	if err != nil {
		t.Fatalf("UserAndOrgs failed: %v", err)
	}
	if username != "testuser" {
		t.Errorf("username = %q, want %q", username, "testuser")
	}
	if len(orgs) != 2 {
		t.Errorf("len(orgs) = %d, want 2", len(orgs))
	}
}

// TestValidateOrgMembership_Success tests successful org membership validation.
func TestValidateOrgMembership_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/installation/repositories":
			w.WriteHeader(http.StatusNotFound)
		case "/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
		case "/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Login: "org1"},
				{Login: "targetorg"},
			}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	username, orgs, err := client.ValidateOrgMembership(ctx, "targetorg")
	if err != nil {
		t.Fatalf("ValidateOrgMembership failed: %v", err)
	}
	if username != "testuser" {
		t.Errorf("username = %q, want %q", username, "testuser")
	}
	if len(orgs) != 2 {
		t.Errorf("len(orgs) = %d, want 2", len(orgs))
	}
}

// TestValidateOrgMembership_NotMember tests validation when user is not a member.
func TestValidateOrgMembership_NotMember(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/installation/repositories":
			w.WriteHeader(http.StatusNotFound)
		case "/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
		case "/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Login: "org1"},
			}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	_, _, err := client.ValidateOrgMembership(ctx, "notmemberorg")
	if err == nil {
		t.Fatal("expected error when user is not a member, got nil")
	}
	if !strings.Contains(err.Error(), "not a member") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestValidateOrgMembership_EmptyOrgName tests validation with empty org name.
func TestValidateOrgMembership_EmptyOrgName(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", nil)
	ctx := context.Background()

	_, _, err := client.ValidateOrgMembership(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty org name, got nil")
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestValidateOrgMembership_InvalidOrgFormat tests validation with invalid org name format.
func TestValidateOrgMembership_InvalidOrgFormat(t *testing.T) {
	t.Parallel()

	client := NewClient("test-token", nil)
	ctx := context.Background()

	invalidNames := []string{
		"org with spaces",
		"org@invalid",
		"org$invalid",
		"org.invalid",
	}

	for _, name := range invalidNames {
		_, _, err := client.ValidateOrgMembership(ctx, name)
		if err == nil {
			t.Errorf("expected error for invalid org name %q, got nil", name)
		}
		if !strings.Contains(err.Error(), "invalid organization name format") {
			t.Errorf("unexpected error for %q: %v", name, err)
		}
	}
}

// TestValidateOrgMembership_CaseInsensitive tests case-insensitive org matching.
func TestValidateOrgMembership_CaseInsensitive(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/installation/repositories":
			w.WriteHeader(http.StatusNotFound)
		case "/user":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
		case "/user/orgs":
			w.WriteHeader(http.StatusOK)
			orgs := []Organization{
				{Login: "TestOrg"},
			}
			_ = json.NewEncoder(w).Encode(orgs)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	_, _, err := client.ValidateOrgMembership(ctx, "testorg")
	if err != nil {
		t.Errorf("case-insensitive matching failed: %v", err)
	}
}

// TestFindPRsForCommit_Success tests successful PR lookup.
func TestFindPRsForCommit_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/commits/") || !strings.HasSuffix(r.URL.Path, "/pulls") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		prs := []map[string]interface{}{
			{"number": 123, "state": "open"},
			{"number": 456, "state": "closed"},
		}
		_ = json.NewEncoder(w).Encode(prs)
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	prNumbers, err := client.FindPRsForCommit(ctx, "owner", "repo", "abc123def456")
	if err != nil {
		t.Fatalf("FindPRsForCommit failed: %v", err)
	}
	if len(prNumbers) != 2 {
		t.Errorf("len(prNumbers) = %d, want 2", len(prNumbers))
	}
	if prNumbers[0] != 123 || prNumbers[1] != 456 {
		t.Errorf("prNumbers = %v, want [123 456]", prNumbers)
	}
}

// TestFindPRsForCommit_EmptyResultRetry tests retry logic on empty result.
func TestFindPRsForCommit_EmptyResultRetry(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusOK)
		if attempts == 1 {
			// First attempt returns empty (simulating GitHub indexing delay)
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
		} else {
			// Second attempt returns PR
			prs := []map[string]interface{}{
				{"number": 123, "state": "open"},
			}
			_ = json.NewEncoder(w).Encode(prs)
		}
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	prNumbers, err := client.FindPRsForCommit(ctx, "owner", "repo", "abc123def456")
	if err != nil {
		t.Fatalf("FindPRsForCommit failed: %v", err)
	}
	if len(prNumbers) != 1 || prNumbers[0] != 123 {
		t.Errorf("prNumbers = %v, want [123]", prNumbers)
	}
	if attempts < 2 {
		t.Errorf("expected at least 2 attempts due to retry logic, got %d", attempts)
	}
}

// TestFindPRsForCommit_NotFound tests 404 response.
func TestFindPRsForCommit_NotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	_, err := client.FindPRsForCommit(ctx, "owner", "repo", "nonexistent123")
	if err == nil {
		t.Fatal("expected error for not found, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestFindPRsForCommit_Unauthorized tests auth failure.
func TestFindPRsForCommit_Unauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient("invalid-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	_, err := client.FindPRsForCommit(ctx, "owner", "repo", "abc123def456")
	if err == nil {
		t.Fatal("expected error for unauthorized, got nil")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserOrganizations_Success tests successful org listing.
func TestUserOrganizations_Success(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/orgs" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		orgs := []Organization{
			{Login: "org1"},
			{Login: "org2"},
			{Login: "org3"},
		}
		_ = json.NewEncoder(w).Encode(orgs)
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user/orgs",
		to:   server.URL + "/user/orgs",
	}

	ctx := context.Background()
	orgs, err := client.userOrganizations(ctx)
	if err != nil {
		t.Fatalf("userOrganizations failed: %v", err)
	}
	if len(orgs) != 3 {
		t.Errorf("len(orgs) = %d, want 3", len(orgs))
	}
}

// TestUserOrganizations_RateLimit tests rate limit handling.
func TestUserOrganizations_RateLimit(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("X-Ratelimit-Remaining", "0")
		w.Header().Set("X-Ratelimit-Reset", "1234567890")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user/orgs",
		to:   server.URL + "/user/orgs",
	}

	ctx := context.Background()
	_, err := client.userOrganizations(ctx)
	if err == nil {
		t.Fatal("expected error for rate limit, got nil")
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

// redirectTransport redirects requests from one URL to another.
type redirectTransport struct {
	from string
	to   string
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() == t.from {
		req.URL, _ = req.URL.Parse(t.to)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// multiPathTransport handles multiple paths by routing to test server.
type multiPathTransport struct {
	server *httptest.Server
}

func (t *multiPathTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite the URL to point to our test server
	newURL := t.server.URL + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	newReq, err := http.NewRequest(req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	// Copy headers
	newReq.Header = req.Header.Clone()
	return http.DefaultTransport.RoundTrip(newReq)
}

// TestContextCancellation tests that context cancellation is respected.
func TestContextCancellation(t *testing.T) {
	t.Parallel()

	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user",
		to:   server.URL + "/user",
	}

	// Create a context that cancels immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

// TestMalformedJSON tests handling of malformed JSON responses.
func TestMalformedJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user",
		to:   server.URL + "/user",
	}

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestResponseBodyReadError tests handling of errors when reading response body.
func TestResponseBodyReadError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		// Write less than promised to trigger read error
		_, _ = w.Write([]byte(`{"login":"test"}`))
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	// Use a custom transport with very small timeout to trigger error
	client.httpClient.Timeout = 1 * time.Nanosecond
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user",
		to:   server.URL + "/user",
	}

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error due to timeout, got nil")
	}
}

// TestLargeResponseBody tests that large responses are limited.
func TestLargeResponseBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write a very large response (> 1MB limit)
		large := strings.Repeat("x", 2*1024*1024)
		_, _ = w.Write([]byte(`{"login":"` + large + `"}`))
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user",
		to:   server.URL + "/user",
	}

	ctx := context.Background()
	// This should not panic and should handle the limited read
	_, err := client.AuthenticatedUser(ctx)
	// The error could be either a parse error (due to truncation) or success if truncated at valid JSON
	// We just want to ensure it doesn't panic or hang
	_ = err
}

// TestBrokenPipeError simulates a broken pipe during response read.
// TestUnexpectedStatusCodes tests handling of various unexpected status codes.
func TestUnexpectedStatusCodes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		statusCode int
		wantRetry  bool
	}{
		{"BadRequest", http.StatusBadRequest, false},
		{"NotFound", http.StatusNotFound, false},
		{"BadGateway", http.StatusBadGateway, true},
		{"ServiceUnavailable", http.StatusServiceUnavailable, true},
		{"GatewayTimeout", http.StatusGatewayTimeout, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			attempts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts++
				w.WriteHeader(tc.statusCode)
			}))
			defer server.Close()

			client := NewClient("test-token", nil)
			client.httpClient.Transport = &redirectTransport{
				from: "https://api.github.com/user",
				to:   server.URL + "/user",
			}

			ctx := context.Background()
			_, err := client.AuthenticatedUser(ctx)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if tc.wantRetry && attempts < 3 {
				t.Errorf("expected retries for status %d, got %d attempts", tc.statusCode, attempts)
			}
			if !tc.wantRetry && attempts > 1 {
				t.Errorf("expected no retries for status %d, got %d attempts", tc.statusCode, attempts)
			}
		})
	}
}

// TestMockClient tests the MockClient implementation.
func TestMockClient(t *testing.T) {
	t.Parallel()

	t.Run("UserAndOrgs success", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "testuser",
			Orgs:     []string{"org1", "org2"},
		}

		ctx := context.Background()
		username, orgs, err := mock.UserAndOrgs(ctx)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if username != "testuser" {
			t.Errorf("username = %q, want %q", username, "testuser")
		}
		if len(orgs) != 2 {
			t.Errorf("len(orgs) = %d, want 2", len(orgs))
		}
		if mock.UserAndOrgsCalls != 1 {
			t.Errorf("UserAndOrgsCalls = %d, want 1", mock.UserAndOrgsCalls)
		}
	})

	t.Run("UserAndOrgs error", func(t *testing.T) {
		t.Parallel()
		mockErr := fmt.Errorf("mock error")
		mock := &MockClient{
			Err: mockErr,
		}

		ctx := context.Background()
		_, _, err := mock.UserAndOrgs(ctx)

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "mock error") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("ValidateOrgMembership success", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "testuser",
			Orgs:     []string{"org1", "org2"},
		}

		ctx := context.Background()
		username, orgs, err := mock.ValidateOrgMembership(ctx, "org1")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if username != "testuser" {
			t.Errorf("username = %q, want %q", username, "testuser")
		}
		if len(orgs) != 2 {
			t.Errorf("len(orgs) = %d, want 2", len(orgs))
		}
		if mock.LastValidatedOrg != "org1" {
			t.Errorf("LastValidatedOrg = %q, want %q", mock.LastValidatedOrg, "org1")
		}
		if mock.ValidateOrgMembershipCalls != 1 {
			t.Errorf("ValidateOrgMembershipCalls = %d, want 1", mock.ValidateOrgMembershipCalls)
		}
	})

	t.Run("ValidateOrgMembership not member", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "testuser",
			Orgs:     []string{"org1", "org2"},
		}

		ctx := context.Background()
		username, orgs, err := mock.ValidateOrgMembership(ctx, "org3")

		if err == nil {
			t.Fatal("expected error for non-member org, got nil")
		}
		if !strings.Contains(err.Error(), "not a member") {
			t.Errorf("unexpected error: %v", err)
		}
		// Should still return username and orgs even on error
		if username != "testuser" {
			t.Errorf("username = %q, want %q", username, "testuser")
		}
		if len(orgs) != 2 {
			t.Errorf("len(orgs) = %d, want 2", len(orgs))
		}
	})

	t.Run("ValidateOrgMembership error", func(t *testing.T) {
		t.Parallel()
		mockErr := fmt.Errorf("mock validation error")
		mock := &MockClient{
			Err: mockErr,
		}

		ctx := context.Background()
		_, _, err := mock.ValidateOrgMembership(ctx, "org1")

		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "mock validation error") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("multiple calls tracking", func(t *testing.T) {
		t.Parallel()
		mock := &MockClient{
			Username: "testuser",
			Orgs:     []string{"org1"},
		}

		ctx := context.Background()

		// Call UserAndOrgs multiple times
		_, _, _ = mock.UserAndOrgs(ctx)
		_, _, _ = mock.UserAndOrgs(ctx)
		_, _, _ = mock.UserAndOrgs(ctx)

		if mock.UserAndOrgsCalls != 3 {
			t.Errorf("UserAndOrgsCalls = %d, want 3", mock.UserAndOrgsCalls)
		}

		// Call ValidateOrgMembership multiple times
		_, _, _ = mock.ValidateOrgMembership(ctx, "org1")
		_, _, _ = mock.ValidateOrgMembership(ctx, "org1")

		if mock.ValidateOrgMembershipCalls != 2 {
			t.Errorf("ValidateOrgMembershipCalls = %d, want 2", mock.ValidateOrgMembershipCalls)
		}
	})
}

// TestAppInstallationInfo_ServerError tests server error with retry.
func TestAppInstallationInfo_ServerError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		// Succeed on third attempt
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"repositories": []map[string]interface{}{
				{
					"owner": map[string]interface{}{
						"login": "testorg",
						"type":  "Organization",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient("ghs_test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/installation/repositories",
		to:   server.URL + "/installation/repositories",
	}

	ctx := context.Background()
	info, err := client.AppInstallationInfo(ctx)
	if err != nil {
		t.Fatalf("expected success after retries, got error: %v", err)
	}
	if info.Account.Login != "testorg" {
		t.Errorf("account login = %q, want %q", info.Account.Login, "testorg")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

// TestAppInstallationInfo_Forbidden tests 403 response.
func TestAppInstallationInfo_Forbidden(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Forbidden"}`))
	}))
	defer server.Close()

	client := NewClient("ghp_user-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/installation/repositories",
		to:   server.URL + "/installation/repositories",
	}

	ctx := context.Background()
	_, err := client.AppInstallationInfo(ctx)
	if err == nil {
		t.Fatal("expected error for forbidden, got nil")
	}
	if !strings.Contains(err.Error(), "not an app installation token") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAppInstallationInfo_Unauthorized tests 401 response.
func TestAppInstallationInfo_Unauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient("invalid-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/installation/repositories",
		to:   server.URL + "/installation/repositories",
	}

	ctx := context.Background()
	_, err := client.AppInstallationInfo(ctx)
	if err == nil {
		t.Fatal("expected error for unauthorized, got nil")
	}
}

// TestUserAndOrgs_AppTokenOnUserAccount tests app token on user account.
func TestUserAndOrgs_AppTokenOnUserAccount(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/installation/repositories" {
			w.WriteHeader(http.StatusOK)
			response := map[string]interface{}{
				"repositories": []map[string]interface{}{
					{
						"owner": map[string]interface{}{
							"login": "testuser",
							"type":  "User",
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(response)
		}
	}))
	defer server.Close()

	client := NewClient("ghs_app-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/installation/repositories",
		to:   server.URL + "/installation/repositories",
	}

	ctx := context.Background()
	username, orgs, err := client.UserAndOrgs(ctx)
	if err != nil {
		t.Fatalf("UserAndOrgs failed: %v", err)
	}
	if username != "app[installation]" {
		t.Errorf("username = %q, want %q", username, "app[installation]")
	}
	if len(orgs) != 1 || orgs[0] != "testuser" {
		t.Errorf("orgs = %v, want [testuser]", orgs)
	}
}

// TestUserOrganizations_Unauthorized tests 401 response.
func TestUserOrganizations_Unauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewClient("invalid-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user/orgs",
		to:   server.URL + "/user/orgs",
	}

	ctx := context.Background()
	_, err := client.userOrganizations(ctx)
	if err == nil {
		t.Fatal("expected error for unauthorized, got nil")
	}
	if !strings.Contains(err.Error(), "invalid GitHub token") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserOrganizations_Forbidden tests 403 without rate limit.
func TestUserOrganizations_Forbidden(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user/orgs",
		to:   server.URL + "/user/orgs",
	}

	ctx := context.Background()
	_, err := client.userOrganizations(ctx)
	if err == nil {
		t.Fatal("expected error for forbidden, got nil")
	}
	if !strings.Contains(err.Error(), "access forbidden") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserOrganizations_ServerError tests server error retry.
func TestUserOrganizations_ServerError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		orgs := []Organization{{Login: "org1"}}
		_ = json.NewEncoder(w).Encode(orgs)
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user/orgs",
		to:   server.URL + "/user/orgs",
	}

	ctx := context.Background()
	orgs, err := client.userOrganizations(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
	if attempts < 2 {
		t.Errorf("expected at least 2 attempts, got %d", attempts)
	}
}

// TestUserOrganizations_MalformedJSON tests handling of malformed JSON.
func TestUserOrganizations_MalformedJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user/orgs",
		to:   server.URL + "/user/orgs",
	}

	ctx := context.Background()
	_, err := client.userOrganizations(ctx)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestFindPRsForCommit_BadGateway tests 502 response.
func TestFindPRsForCommit_BadGateway(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	_, err := client.FindPRsForCommit(ctx, "owner", "repo", "abc123def456")
	if err == nil {
		t.Fatal("expected error for bad gateway, got nil")
	}
	if attempts < 3 {
		t.Errorf("expected retries, got %d attempts", attempts)
	}
}

// TestFindPRsForCommit_MalformedJSON tests handling of malformed JSON response.
func TestFindPRsForCommit_MalformedJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid`))
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	_, err := client.FindPRsForCommit(ctx, "owner", "repo", "abc123def456")
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAuthenticatedUser_Forbidden tests 403 without rate limit header.
func TestAuthenticatedUser_Forbidden(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Forbidden"}`))
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user",
		to:   server.URL + "/user",
	}

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for forbidden, got nil")
	}
	if !strings.Contains(err.Error(), "access forbidden") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAuthenticatedUser_BadGateway tests 502 response.
func TestAuthenticatedUser_BadGateway(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user",
		to:   server.URL + "/user",
	}

	ctx := context.Background()
	user, err := client.AuthenticatedUser(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if user.Login != "testuser" {
		t.Errorf("username = %q, want %q", user.Login, "testuser")
	}
	if attempts < 2 {
		t.Errorf("expected at least 2 attempts, got %d", attempts)
	}
}

// TestAuthenticatedUser_ServiceUnavailable tests 503 response.
func TestAuthenticatedUser_ServiceUnavailable(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user",
		to:   server.URL + "/user",
	}

	ctx := context.Background()
	_, err := client.AuthenticatedUser(ctx)
	if err == nil {
		t.Fatal("expected error for service unavailable, got nil")
	}
	if attempts < 3 {
		t.Errorf("expected retries, got %d attempts", attempts)
	}
}

// TestAppInstallationInfo_MalformedJSON tests handling of malformed JSON.
func TestAppInstallationInfo_MalformedJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	client := NewClient("ghs_test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/installation/repositories",
		to:   server.URL + "/installation/repositories",
	}

	ctx := context.Background()
	_, err := client.AppInstallationInfo(ctx)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserAndOrgs_TokenTypeDetection tests token type logging.
func TestUserAndOrgs_TokenTypeDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		token     string
		tokenType string
	}{
		{"personal access token", "ghp_1234567890abcdefghij", "personal_access_token"},
		{"oauth token", "gho_1234567890abcdefghij", "oauth_token"},
		{"server to server", "ghs_1234567890abcdefghij", "server_to_server"},
		{"legacy token", strings.Repeat("a", 40), "legacy_token"},
		{"unknown token", "xyz_123", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/installation/repositories":
					w.WriteHeader(http.StatusNotFound)
				case "/user":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(User{Login: "testuser"})
				case "/user/orgs":
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode([]Organization{})
				}
			}))
			defer server.Close()

			client := NewClient(tt.token, nil)
			client.httpClient.Transport = &multiPathTransport{server: server}

			ctx := context.Background()
			_, _, err := client.UserAndOrgs(ctx)
			// We don't care about the result, just that it exercises the token type detection
			_ = err
		})
	}
}

// TestFindPRsForCommit_ServiceUnavailable tests 503 with retries.
func TestFindPRsForCommit_ServiceUnavailable(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	_, err := client.FindPRsForCommit(ctx, "owner", "repo", "abc123def456")
	if err == nil {
		t.Fatal("expected error for service unavailable, got nil")
	}
	if attempts < 3 {
		t.Errorf("expected retries, got %d attempts", attempts)
	}
}

// TestFindPRsForCommit_Forbidden tests 403 response.
func TestFindPRsForCommit_Forbidden(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	_, err := client.FindPRsForCommit(ctx, "owner", "repo", "abc123def456")
	if err == nil {
		t.Fatal("expected error for forbidden, got nil")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestUserOrganizations_BadGateway tests 502 response.
func TestUserOrganizations_BadGateway(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		orgs := []Organization{{Login: "org1"}}
		_ = json.NewEncoder(w).Encode(orgs)
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user/orgs",
		to:   server.URL + "/user/orgs",
	}

	ctx := context.Background()
	orgs, err := client.userOrganizations(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if len(orgs) != 1 {
		t.Errorf("len(orgs) = %d, want 1", len(orgs))
	}
	if attempts < 2 {
		t.Errorf("expected at least 2 attempts, got %d", attempts)
	}
}

// TestAppInstallationInfo_BadGateway tests 502 response.
func TestAppInstallationInfo_BadGateway(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"repositories": []map[string]interface{}{
				{
					"owner": map[string]interface{}{
						"login": "testorg",
						"type":  "Organization",
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient("ghs_test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/installation/repositories",
		to:   server.URL + "/installation/repositories",
	}

	ctx := context.Background()
	info, err := client.AppInstallationInfo(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if info.Account.Login != "testorg" {
		t.Errorf("account login = %q, want %q", info.Account.Login, "testorg")
	}
	if attempts < 2 {
		t.Errorf("expected at least 2 attempts, got %d", attempts)
	}
}

func TestFindPRsForCommit_PersistentEmptyResult(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Always return empty (push to main)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	prs, err := client.FindPRsForCommit(ctx, "owner", "repo", "abc123def456")
	if err != nil {
		t.Fatalf("expected success with empty result, got: %v", err)
	}
	if len(prs) != 0 {
		t.Errorf("prs = %v, want []", prs)
	}
	if attempts < 2 {
		t.Errorf("expected at least 2 attempts for empty result, got %d", attempts)
	}
}

func TestFindPRsForCommit_NetworkError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// First 2 attempts: close connection to simulate network error
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("webserver doesn't support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			return
		}
		// Third attempt: success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"number": 456, "state": "open"}]`))
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &multiPathTransport{server: server}

	ctx := context.Background()
	prs, err := client.FindPRsForCommit(ctx, "owner", "repo", "def456abc123")
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if len(prs) != 1 || prs[0] != 456 {
		t.Errorf("prs = %v, want [456]", prs)
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

func TestUserOrganizations_RateLimitRetry(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			// First attempt: rate limit
			w.Header().Set("X-Ratelimit-Remaining", "0")
			w.Header().Set("X-Ratelimit-Reset", "1234567890")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message": "API rate limit exceeded"}`))
			return
		}
		// Second attempt: success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"login": "org1"}, {"login": "org2"}]`))
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user/orgs",
		to:   server.URL + "/user/orgs",
	}

	ctx := context.Background()
	orgs, err := client.userOrganizations(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if len(orgs) != 2 {
		t.Errorf("len(orgs) = %d, want 2", len(orgs))
	}
	if attempts < 2 {
		t.Errorf("expected at least 2 attempts, got %d", attempts)
	}
}

func TestAppInstallationInfo_NetworkError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// First 2 attempts: close connection
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("webserver doesn't support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			return
		}
		// Third attempt: success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"repositories": [{"owner": {"login": "testorg", "type": "Organization"}}]}`))
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/installation/repositories",
		to:   server.URL + "/installation/repositories",
	}

	ctx := context.Background()
	info, err := client.AppInstallationInfo(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if info.Account.Login != "testorg" {
		t.Errorf("account login = %q, want %q", info.Account.Login, "testorg")
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}

func TestUserOrganizations_NetworkError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// First 2 attempts: close connection
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("webserver doesn't support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			return
		}
		// Third attempt: success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"login": "org1"}, {"login": "org2"}]`))
	}))
	defer server.Close()

	client := NewClient("test-token", nil)
	client.httpClient.Transport = &redirectTransport{
		from: "https://api.github.com/user/orgs",
		to:   server.URL + "/user/orgs",
	}

	ctx := context.Background()
	orgs, err := client.userOrganizations(ctx)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if len(orgs) != 2 {
		t.Errorf("len(orgs) = %d, want 2", len(orgs))
	}
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts)
	}
}
