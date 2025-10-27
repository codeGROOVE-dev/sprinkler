package client

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestStopMultipleCalls verifies that calling Stop() multiple times is safe
// and doesn't panic with "close of closed channel".
func TestStopMultipleCalls(t *testing.T) {
	// Create a client with minimal config
	client, err := New(Config{
		ServerURL:    "ws://localhost:8080",
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true, // Disable reconnect to make test faster
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Start the client in a goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		// Expected to fail to connect, but that's ok for this test
		if err := client.Start(ctx); err != nil {
			// Error is expected in tests - client can't connect to non-existent server
		}
	}()

	// Give it a moment to initialize
	time.Sleep(10 * time.Millisecond)

	// Call Stop() multiple times concurrently
	// This should NOT panic with "close of closed channel"
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client.Stop() // Should be safe to call multiple times
		}()
	}

	// Wait for all Stop() calls to complete
	wg.Wait()

	// If we get here without a panic, the test passes
}

// TestStopBeforeStart verifies that calling Stop() before Start() is safe.
func TestStopBeforeStart(t *testing.T) {
	client, err := New(Config{
		ServerURL:    "ws://localhost:8080",
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Call Stop() before Start()
	client.Stop()

	// Now try to start - should exit cleanly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = client.Start(ctx)
	// We expect either context.DeadlineExceeded or "stop requested"
	if err == nil {
		t.Error("Expected Start() to fail after Stop(), but it succeeded")
	}
}
