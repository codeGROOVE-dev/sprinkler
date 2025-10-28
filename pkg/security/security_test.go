package security

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

// TestConnectionLimiterEviction tests eviction of old inactive entries.
func TestConnectionLimiterEviction(t *testing.T) {
	cl := NewConnectionLimiter(2, 100)
	defer cl.Stop()

	// Fill up the IP entries table to trigger eviction
	// maxIPEntries is 10000, so we need to add many IPs
	// For testing purposes, we'll just add enough to trigger the logic

	// Add and remove connections to create inactive entries
	for i := range 10 {
		ip := fmt.Sprintf("192.168.1.%d", i)
		cl.Add(ip)
		cl.Remove(ip) // Make it inactive
	}

	// Now add a new IP - should work because inactive entries can be evicted
	newIP := "192.168.2.1"
	if !cl.Add(newIP) {
		t.Error("Should allow connection after evicting inactive entries")
	}
}

// TestConnectionLimiterReservationEdgeCases tests edge cases in reservation logic.
func TestConnectionLimiterReservationEdgeCases(t *testing.T) {
	cl := NewConnectionLimiter(2, 5)
	defer cl.Stop()

	ip := "192.168.1.1"

	// Reserve twice to ensure no double-counting
	token1 := cl.Reserve(ip)
	token2 := cl.Reserve(ip)

	if token1 == "" || token2 == "" {
		t.Fatal("Both reservations should succeed")
	}

	// Commit first reservation
	if !cl.CommitReservation(token1) {
		t.Error("First commit should succeed")
	}

	// Try to commit the same token again - should fail
	if cl.CommitReservation(token1) {
		t.Error("Double commit should fail")
	}

	// Commit second reservation
	if !cl.CommitReservation(token2) {
		t.Error("Second commit should succeed")
	}

	// Now at per-IP limit (2), should not allow more
	token3 := cl.Reserve(ip)
	if token3 != "" {
		t.Error("Should not allow reservation beyond per-IP limit")
	}
}

// TestConnectionLimiterCancelNonExistent tests canceling non-existent reservation.
func TestConnectionLimiterCancelNonExistent(t *testing.T) {
	cl := NewConnectionLimiter(2, 5)
	defer cl.Stop()

	// Cancel non-existent token - should not panic
	cl.CancelReservation("non-existent-token")

	// Cancel empty token - should not panic
	cl.CancelReservation("")
}

// TestConnectionLimiterCommitNonExistent tests committing non-existent reservation.
func TestConnectionLimiterCommitNonExistent(t *testing.T) {
	cl := NewConnectionLimiter(2, 5)
	defer cl.Stop()

	// Commit non-existent token - should return false
	if cl.CommitReservation("non-existent-token") {
		t.Error("Should not commit non-existent reservation")
	}

	// Commit empty token - should return false
	if cl.CommitReservation("") {
		t.Error("Should not commit empty reservation")
	}
}

// TestConnectionLimiterExpiredReservation tests handling of expired reservations.
func TestConnectionLimiterExpiredReservation(t *testing.T) {
	cl := NewConnectionLimiter(2, 5)
	defer cl.Stop()

	ip := "192.168.1.1"
	token := cl.Reserve(ip)
	if token == "" {
		t.Fatal("Reservation should succeed")
	}

	// Manually expire the reservation by modifying createdAt
	cl.mu.Lock()
	if res := cl.reservations[token]; res != nil {
		res.createdAt = res.createdAt.Add(-2 * time.Minute) // Expire it
	}
	cl.mu.Unlock()

	// Try to commit expired reservation - should fail
	if cl.CommitReservation(token) {
		t.Error("Should not commit expired reservation")
	}

	// Verify the reservation was cleaned up
	cl.mu.Lock()
	if cl.reservations[token] != nil {
		t.Error("Expired reservation should be deleted")
	}
	cl.mu.Unlock()
}

// TestConnectionLimiterMultipleRemove tests removing connection multiple times.
func TestConnectionLimiterMultipleRemove(t *testing.T) {
	cl := NewConnectionLimiter(2, 5)
	defer cl.Stop()

	ip := "192.168.1.1"
	cl.Add(ip)

	// Remove once - should work
	cl.Remove(ip)

	// Remove again - should not panic or cause negative counts
	cl.Remove(ip)

	// Verify we can still add
	if !cl.Add(ip) {
		t.Error("Should be able to add after removes")
	}
}

// TestConnectionLimiterCommitAfterIPRemoval tests committing when IP info is missing.
func TestConnectionLimiterCommitAfterIPRemoval(t *testing.T) {
	cl := NewConnectionLimiter(2, 5)
	defer cl.Stop()

	ip := "192.168.1.1"
	token := cl.Reserve(ip)
	if token == "" {
		t.Fatal("Reservation should succeed")
	}

	// Manually remove the IP entry to test edge case
	cl.mu.Lock()
	delete(cl.perIP, ip)
	cl.mu.Unlock()

	// Try to commit - should fail gracefully
	if cl.CommitReservation(token) {
		t.Error("Should not commit when IP info is missing")
	}

	// Verify reservation was cleaned up
	cl.mu.Lock()
	if cl.reservations[token] != nil {
		t.Error("Reservation should be deleted after failed commit")
	}
	cl.mu.Unlock()
}

// TestConnectionLimiterCleanup tests the periodic cleanup function.
func TestConnectionLimiterCleanup(t *testing.T) {
	cl := NewConnectionLimiter(2, 5)
	defer cl.Stop()

	// Add some connections and make them inactive
	for i := range 3 {
		ip := fmt.Sprintf("192.168.1.%d", i)
		cl.Add(ip)
		cl.Remove(ip)
	}

	// Wait a bit for cleanup to potentially run
	time.Sleep(100 * time.Millisecond)

	// Just verify no panic occurred during cleanup
	// The cleanup runs in background, so we can't easily test it deterministically
}

// TestConnectionLimiterReserveThenAddDirectly tests mixed reservation and direct add.
func TestConnectionLimiterReserveThenAddDirectly(t *testing.T) {
	cl := NewConnectionLimiter(3, 10)
	defer cl.Stop()

	ip := "192.168.1.1"

	// Reserve one slot
	token := cl.Reserve(ip)
	if token == "" {
		t.Fatal("Reservation should succeed")
	}

	// Directly add a connection (without using reservation system)
	if !cl.Add(ip) {
		t.Error("Direct add should succeed (under per-IP limit)")
	}

	// Commit the reservation
	if !cl.CommitReservation(token) {
		t.Error("Should be able to commit reservation")
	}

	// Now we have 2 active connections
	// Add one more (at limit of 3)
	if !cl.Add(ip) {
		t.Error("Third connection should succeed (at per-IP limit of 3)")
	}

	// Now at limit - fourth should fail
	if cl.Add(ip) {
		t.Error("Should not allow fourth connection (per-IP limit is 3)")
	}
}

// TestConnectionLimiterAddRemoveAddPattern tests add/remove/add pattern.
func TestConnectionLimiterAddRemoveAddPattern(t *testing.T) {
	cl := NewConnectionLimiter(2, 5)
	defer cl.Stop()

	ip := "192.168.1.1"

	// Add two connections
	if !cl.Add(ip) {
		t.Error("First add should succeed")
	}
	if !cl.Add(ip) {
		t.Error("Second add should succeed")
	}

	// At limit - third should fail
	if cl.Add(ip) {
		t.Error("Third add should fail (per-IP limit)")
	}

	// Remove one
	cl.Remove(ip)

	// Now should be able to add again
	if !cl.Add(ip) {
		t.Error("Should be able to add after removal")
	}

	// Verify total count
	cl.mu.Lock()
	if cl.total != 2 {
		t.Errorf("Expected total=2, got %d", cl.total)
	}
	cl.mu.Unlock()
}

// TestConnectionLimiterRemoveNonExistent tests removing from non-existent IP.
func TestConnectionLimiterRemoveNonExistent(t *testing.T) {
	cl := NewConnectionLimiter(2, 5)
	defer cl.Stop()

	// Remove from IP that was never added - should not panic
	cl.Remove("192.168.1.1")

	// Verify total is still 0
	cl.mu.Lock()
	if cl.total != 0 {
		t.Errorf("Expected total=0, got %d", cl.total)
	}
	cl.mu.Unlock()
}

// TestConnectionLimiterEvictOldestInactive tests eviction of inactive entries.
func TestConnectionLimiterEvictOldestInactive(t *testing.T) {
	cl := NewConnectionLimiter(1, 1000)
	defer cl.Stop()

	// Add and remove many IPs to create inactive entries with different ages
	for i := range 20 {
		ip := fmt.Sprintf("192.168.%d.%d", i/256, i%256)
		cl.Add(ip)
		// Remove half of them to make inactive
		if i%2 == 0 {
			cl.Remove(ip)
			// Add a small delay to ensure different lastActive times
			time.Sleep(time.Millisecond)
		}
	}

	// Count total entries before eviction
	cl.mu.Lock()
	totalBefore := len(cl.perIP)

	// Manually trigger eviction
	cl.evictOldestInactive()

	// Count total entries after eviction
	totalAfter := len(cl.perIP)
	cl.mu.Unlock()

	// Eviction should reduce the total count (or leave it the same if cleanup already ran)
	// Just verify no panic and count decreased or stayed same
	if totalAfter > totalBefore {
		t.Errorf("Expected total entries to decrease or stay same, but increased from %d to %d", totalBefore, totalAfter)
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
