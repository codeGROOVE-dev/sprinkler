package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(5, time.Second)
	defer rl.stop()
	
	ip := "192.168.1.1"

	// Should allow first 5 requests
	for i := 0; i < 5; i++ {
		if !rl.allow(ip) {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied
	if rl.allow(ip) {
		t.Error("6th request should be denied")
	}

	// Note: Our simplified rate limiter resets every minute,
	// not every second, so we can't test the reset behavior easily
}

func TestConnectionLimiter(t *testing.T) {
	cl := newConnectionLimiter(2, 5)

	// Test per-IP limit
	ip1 := "192.168.1.1"
	if !cl.add(ip1) {
		t.Error("first connection should be allowed")
	}
	if !cl.add(ip1) {
		t.Error("second connection should be allowed")
	}
	if cl.add(ip1) {
		t.Error("third connection should be denied (per-IP limit)")
	}

	// Test total limit
	ip2 := "192.168.1.2"
	ip3 := "192.168.1.3"
	cl.add(ip2)
	cl.add(ip2)
	cl.add(ip3)

	// Should hit total limit
	ip4 := "192.168.1.4"
	if cl.add(ip4) {
		t.Error("should hit total connection limit")
	}

	// Remove a connection
	cl.remove(ip1)

	// Should allow new connection after removal
	if !cl.add(ip4) {
		t.Error("should allow connection after removal")
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		want       string
	}{
		{
			name:       "direct connection",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1:12345",
			want:       "192.168.1.1",
		},
		{
			name: "ignores X-Forwarded-For",
			headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
			},
			remoteAddr: "192.168.1.1:12345",
			want:       "192.168.1.1",
		},
		{
			name: "ignores X-Forwarded-For multiple IPs",
			headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1, 10.0.0.2, 10.0.0.3",
			},
			remoteAddr: "192.168.1.1:12345",
			want:       "192.168.1.1",
		},
		{
			name: "ignores X-Real-IP",
			headers: map[string]string{
				"X-Real-IP": "10.0.0.1",
			},
			remoteAddr: "192.168.1.1:12345",
			want:       "192.168.1.1",
		},
		{
			name: "no port in RemoteAddr",
			headers: map[string]string{},
			remoteAddr: "192.168.1.1",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			if got := getClientIP(req); got != tt.want {
				t.Errorf("getClientIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateSubscription(t *testing.T) {
	tests := []struct {
		name    string
		sub     Subscription
		wantErr bool
	}{
		{
			name:    "valid username",
			sub:     Subscription{Username: "valid-user123"},
			wantErr: false,
		},
		{
			name:    "username too long",
			sub:     Subscription{Username: "this-username-is-way-too-long-for-github-limits"},
			wantErr: true,
		},
		{
			name:    "username with invalid chars",
			sub:     Subscription{Username: "user@name"},
			wantErr: true,
		},
		{
			name:    "valid PR URL",
			sub:     Subscription{PRURL: "https://github.com/owner/repo/pull/123"},
			wantErr: false,
		},
		{
			name:    "PR URL too long",
			sub:     Subscription{PRURL: "https://github.com/" + string(make([]byte, 500))},
			wantErr: true,
		},
		{
			name:    "PR URL not GitHub",
			sub:     Subscription{PRURL: "https://gitlab.com/owner/repo/pull/123"},
			wantErr: true,
		},
		{
			name:    "PR URL with path traversal",
			sub:     Subscription{PRURL: "https://github.com/../etc/passwd"},
			wantErr: true,
		},
		{
			name:    "valid repository URL",
			sub:     Subscription{Repository: "https://github.com/owner/repo"},
			wantErr: false,
		},
		{
			name:    "repository URL not GitHub",
			sub:     Subscription{Repository: "https://example.com/repo"},
			wantErr: true,
		},
		{
			name: "all valid fields",
			sub: Subscription{
				Username:   "user",
				PRURL:      "https://github.com/owner/repo/pull/1",
				Repository: "https://github.com/owner/repo",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSubscription(&tt.sub)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSubscription() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := securityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}

	for header, expected := range expectedHeaders {
		if got := w.Header().Get(header); got != expected {
			t.Errorf("header %s = %q, want %q", header, got, expected)
		}
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	rl := newRateLimiter(2, time.Minute)
	defer rl.stop()

	handler := rateLimitMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected status 200, got %d", i+1, w.Code)
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", w.Code)
	}
}

