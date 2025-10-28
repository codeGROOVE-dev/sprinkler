package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConnectionLimiter(t *testing.T) {
	cl := NewConnectionLimiter(2, 5)

	// Test per-IP limit
	ip1 := "192.168.1.1"
	if !cl.Add(ip1) {
		t.Error("first connection should be allowed")
	}
	if !cl.Add(ip1) {
		t.Error("second connection should be allowed")
	}
	if cl.Add(ip1) {
		t.Error("third connection should be denied (per-IP limit)")
	}

	// Test total limit
	ip2 := "192.168.1.2"
	ip3 := "192.168.1.3"
	cl.Add(ip2)
	cl.Add(ip2)
	cl.Add(ip3)

	// Should hit total limit
	ip4 := "192.168.1.4"
	if cl.Add(ip4) {
		t.Error("should hit total connection limit")
	}

	// Remove a connection
	cl.Remove(ip1)

	// Should allow new connection after removal
	if !cl.Add(ip4) {
		t.Error("should allow connection after removal")
	}
}

func TestClientIP(t *testing.T) {
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
			name:       "no port in RemoteAddr",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1",
			want:       "192.168.1.1", // Should return the IP even without port
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			if got := ClientIP(req); got != tt.want {
				t.Errorf("ClientIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
