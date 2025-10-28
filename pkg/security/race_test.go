package security

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConnectionLimiterReservation verifies the reservation pattern prevents TOCTOU.
// This test should PASS consistently with the new reservation-based approach.
//
// Run with: go test -race -run TestConnectionLimiterReservation -v
func TestConnectionLimiterReservation(t *testing.T) {
	const maxPerIP = 10
	const concurrent = 50 // Try to reserve 50 connections with limit of 10

	limiter := NewConnectionLimiter(maxPerIP, 1000)
	defer limiter.Stop()

	ip := "192.168.1.1"

	var wg sync.WaitGroup
	var reserveSuccess int32 // How many times Reserve returned a token
	var commitSuccess int32  // How many times CommitReservation succeeded
	var commitFailed int32   // How many times CommitReservation failed

	// Launch many goroutines simultaneously trying to reserve and commit connections
	for i := range concurrent {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Reserve a slot (this is the critical section - atomic operation)
			token := limiter.Reserve(ip)
			if token == "" {
				// Limit reached - expected behavior
				return
			}

			atomic.AddInt32(&reserveSuccess, 1)

			// Simulate work between reserve and commit (auth, WebSocket upgrade, etc.)
			time.Sleep(time.Microsecond * 10)

			// Commit the reservation
			if limiter.CommitReservation(token) {
				atomic.AddInt32(&commitSuccess, 1)
				t.Logf("goroutine %d: Reserve=SUCCESS, Commit=SUCCESS", id)
			} else {
				atomic.AddInt32(&commitFailed, 1)
				t.Logf("goroutine %d: Reserve=SUCCESS, Commit=FAILED (reservation expired)", id)
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Results:")
	t.Logf("  Reserve succeeded: %d times", reserveSuccess)
	t.Logf("  Commit succeeded: %d times (should be %d)", commitSuccess, maxPerIP)
	t.Logf("  Commit failed: %d times", commitFailed)
	t.Logf("  Expected at limit: %d", maxPerIP)

	// Verify the actual limit is enforced
	if commitSuccess > maxPerIP {
		t.Errorf("CRITICAL: Connection limit exceeded! Got %d, want <= %d", commitSuccess, maxPerIP)
	}

	// With reservation pattern, all successful reserves should commit
	// (unless they expired, which shouldn't happen with 10us sleep)
	if commitFailed > 0 {
		t.Errorf("Unexpected commit failures: %d (might be timing-dependent)", commitFailed)
	}

	// The key test: reserves should be at or near the limit (no TOCTOU gap)
	if reserveSuccess > maxPerIP*2 {
		t.Errorf("Too many reservations succeeded: got %d, want <= %d", reserveSuccess, maxPerIP*2)
	}

	// Show final connection count
	info := limiter.perIP[ip]
	if info != nil {
		t.Logf("Final connection count for %s: %d (reservations: %d)", ip, info.count, info.reservations)
	}

	// Verify no leaked reservations
	limiter.mu.Lock()
	if len(limiter.reservations) > 0 {
		t.Errorf("Leaked reservations: %d", len(limiter.reservations))
	}
	limiter.mu.Unlock()
}

// TestConnectionLimiterTOCTOU_Documentation documents the OLD time-of-check-time-of-use bug
// that existed before we implemented the reservation pattern.
//
// This test uses the DEPRECATED CanAdd/Add pattern and is EXPECTED to demonstrate the race.
// We skip it by default because:
// 1. Production code no longer uses this pattern (uses Reserve/Commit instead)
// 2. It's kept purely for documentation
// 3. We don't want it to fail CI/CD
//
// To run this test explicitly: go test -race -run TestConnectionLimiterTOCTOU_Documentation -v
func TestConnectionLimiterTOCTOU_Documentation(t *testing.T) {
	t.Skip("Skipping TOCTOU documentation test - demonstrates OLD buggy pattern that's no longer used")

	const maxPerIP = 10
	const concurrent = 50 // Try to add 50 connections with limit of 10

	limiter := NewConnectionLimiter(maxPerIP, 1000)
	defer limiter.Stop()

	ip := "192.168.1.1"

	var wg sync.WaitGroup
	var canAddSuccess int32 // How many times CanAdd returned true
	var addSuccess int32    // How many times Add actually succeeded
	var addFailed int32     // How many times Add failed despite CanAdd=true

	// Launch many goroutines simultaneously trying to add connections
	// This simulates multiple HTTP handlers racing to add connections
	for i := range concurrent {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// TOCTOU pattern: Check if we can add (OLD buggy pattern)
			if limiter.CanAdd(ip) {
				atomic.AddInt32(&canAddSuccess, 1)

				// Simulate work between check and add (auth, WebSocket upgrade, etc.)
				// This is where the race condition window opens
				time.Sleep(time.Microsecond * 10)

				// Try to add (OLD buggy pattern)
				if limiter.Add(ip) {
					atomic.AddInt32(&addSuccess, 1)
					t.Logf("goroutine %d: CanAdd=true, Add=SUCCESS", id)
				} else {
					atomic.AddInt32(&addFailed, 1)
					t.Logf("goroutine %d: CanAdd=true, Add=FAILED ⚠️  TOCTOU BUG!", id)
				}
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Results with OLD CanAdd/Add pattern:")
	t.Logf("  CanAdd returned true: %d times", canAddSuccess)
	t.Logf("  Add succeeded: %d times (should be %d)", addSuccess, maxPerIP)
	t.Logf("  Add failed after CanAdd=true: %d times ⚠️", addFailed)
	t.Logf("")
	t.Logf("This demonstrates why the Reserve/Commit pattern was necessary.")
	t.Logf("Production code now uses Reserve/Commit which eliminates this race.")

	// Verify the actual limit is enforced
	if addSuccess > maxPerIP {
		t.Errorf("CRITICAL: Connection limit exceeded! Got %d, want <= %d", addSuccess, maxPerIP)
	}

	// Document that the bug exists with this pattern
	if addFailed > 0 {
		t.Logf("✓ TOCTOU bug successfully demonstrated: %d failures", addFailed)
		t.Logf("  (This is expected with the old CanAdd/Add pattern)")
	}

	// Show final connection count
	info := limiter.perIP[ip]
	if info != nil {
		t.Logf("Final connection count for %s: %d", ip, info.count)
	}
}

// TestConnectionLimiterConcurrentAccess verifies basic thread safety
// without the TOCTOU pattern.
func TestConnectionLimiterConcurrentAccess(t *testing.T) {
	limiter := NewConnectionLimiter(5, 100)
	defer limiter.Stop()

	var wg sync.WaitGroup

	// Test concurrent Add/Remove from multiple IPs
	for i := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := "192.168.1." + string(rune('1'+id))

			// Rapid add/remove cycles
			for range 100 {
				if limiter.Add(ip) {
					time.Sleep(time.Microsecond)
					limiter.Remove(ip)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify no connections leaked
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	if limiter.total != 0 {
		t.Errorf("Connection leak detected: total=%d, want 0", limiter.total)
	}

	if len(limiter.perIP) != 0 {
		t.Errorf("perIP map not empty: size=%d", len(limiter.perIP))
	}
}

// TestConnectionLimiterReservationCancellation tests the cancellation path.
func TestConnectionLimiterReservationCancellation(t *testing.T) {
	limiter := NewConnectionLimiter(10, 1000)
	defer limiter.Stop()

	ip := "192.168.1.1"

	// Reserve slots
	tokens := make([]string, 5)
	for i := range tokens {
		tokens[i] = limiter.Reserve(ip)
		if tokens[i] == "" {
			t.Fatalf("Failed to reserve slot %d", i)
		}
	}

	// Verify reservations are tracked
	info := limiter.perIP[ip]
	if info == nil || info.reservations != 5 {
		t.Errorf("Expected 5 reservations, got %d", info.reservations)
	}

	// Cancel half of them
	for i := range 3 {
		limiter.CancelReservation(tokens[i])
	}

	// Verify cancellation
	limiter.mu.Lock()
	if len(limiter.reservations) != 2 {
		t.Errorf("Expected 2 reservations after cancellation, got %d", len(limiter.reservations))
	}
	limiter.mu.Unlock()

	// Commit the rest
	for i := 3; i < 5; i++ {
		if !limiter.CommitReservation(tokens[i]) {
			t.Errorf("Failed to commit reservation %d", i)
		}
	}

	// Verify final state
	if info.count != 2 {
		t.Errorf("Expected 2 connections, got %d", info.count)
	}
	if info.reservations != 0 {
		t.Errorf("Expected 0 reservations, got %d", info.reservations)
	}
}

// TestConnectionLimiterReservationExpiration tests that expired reservations are cleaned up.
func TestConnectionLimiterReservationExpiration(t *testing.T) {
	limiter := NewConnectionLimiter(10, 1000)
	defer limiter.Stop()

	ip := "192.168.1.1"

	// Reserve a slot
	token := limiter.Reserve(ip)
	if token == "" {
		t.Fatal("Failed to reserve slot")
	}

	// Wait for expiration (reservationTimeout = 10s, so we can't wait that long in tests)
	// Instead, test that commit fails after manual cleanup
	limiter.mu.Lock()
	// Artificially expire the reservation by backdating it
	if res := limiter.reservations[token]; res != nil {
		res.createdAt = time.Now().Add(-11 * time.Second)
	}
	limiter.mu.Unlock()

	// Trigger cleanup
	limiter.cleanup()

	// Try to commit - should fail
	if limiter.CommitReservation(token) {
		t.Error("Expected commit to fail for expired reservation")
	}

	// Verify reservation was cleaned up
	limiter.mu.Lock()
	if len(limiter.reservations) != 0 {
		t.Errorf("Expected 0 reservations after cleanup, got %d", len(limiter.reservations))
	}
	limiter.mu.Unlock()
}

// TestConnectionLimiterTotalLimit tests that total connection limit is enforced.
func TestConnectionLimiterTotalLimit(t *testing.T) {
	limiter := NewConnectionLimiter(5, 10) // 5 per IP, 10 total
	defer limiter.Stop()

	// Reserve from two different IPs
	for i := range 2 {
		ip := "192.168.1." + string(rune('1'+i))
		for range 5 {
			token := limiter.Reserve(ip)
			if token == "" {
				t.Fatalf("Failed to reserve slot for %s", ip)
			}
			if !limiter.CommitReservation(token) {
				t.Fatalf("Failed to commit reservation for %s", ip)
			}
		}
	}

	// Try to reserve one more - should fail due to total limit
	token := limiter.Reserve("192.168.1.3")
	if token != "" {
		t.Error("Expected reservation to fail due to total limit")
	}

	// Clean up one connection
	limiter.Remove("192.168.1.1")

	// Now reservation should succeed
	token = limiter.Reserve("192.168.1.3")
	if token == "" {
		t.Error("Expected reservation to succeed after freeing a slot")
	}
}

// BenchmarkConnectionLimiterReservation benchmarks the new reservation pattern.
func BenchmarkConnectionLimiterReservation(b *testing.B) {
	limiter := NewConnectionLimiter(100, 10000)
	defer limiter.Stop()

	ip := "192.168.1.1"

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			token := limiter.Reserve(ip)
			if token != "" {
				if limiter.CommitReservation(token) {
					limiter.Remove(ip)
				}
			}
		}
	})
}

// BenchmarkConnectionLimiterTOCTOU benchmarks the OLD TOCTOU pattern
// to see how often the race condition occurs under load.
func BenchmarkConnectionLimiterTOCTOU(b *testing.B) {
	limiter := NewConnectionLimiter(10, 1000)
	defer limiter.Stop()

	ip := "192.168.1.1"

	var toctouCount int64

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if limiter.CanAdd(ip) {
				if !limiter.Add(ip) {
					atomic.AddInt64(&toctouCount, 1)
				} else {
					limiter.Remove(ip) // Clean up for next iteration
				}
			}
		}
	})

	b.ReportMetric(float64(toctouCount), "toctou_failures")

	if toctouCount > 0 {
		b.Logf("⚠️  TOCTOU failures observed: %d", toctouCount)
	}
}
