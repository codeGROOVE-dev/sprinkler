package security

import (
	"net"
	"net/http"
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
