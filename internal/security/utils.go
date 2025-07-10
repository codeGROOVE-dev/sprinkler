package security

import (
	"crypto/rand"
	"math/big"
	"net"
	"net/http"
)

// GetClientIP extracts the client IP from the request.
// We only use RemoteAddr to avoid header spoofing.
func GetClientIP(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// GenerateRandomString generates a cryptographically secure random string.
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}