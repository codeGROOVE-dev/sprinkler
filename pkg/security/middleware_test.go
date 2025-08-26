package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCombinedMiddleware_SecurityHeaders(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	handler := CombinedMiddleware(rl, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "192.168.1.1:12345"
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

func TestCombinedMiddleware_RateLimit(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)

	handler := CombinedMiddleware(rl, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First two requests should succeed
	for i := range 2 {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected status 200, got %d", i+1, w.Code)
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", w.Code)
	}
}
