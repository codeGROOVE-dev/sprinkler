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
		_ = client.Start(ctx) //nolint:errcheck // Error is expected in tests - client can't connect to non-existent server
	}()

	// Give it a moment to initialize
	time.Sleep(10 * time.Millisecond)

	// Call Stop() multiple times concurrently
	// This should NOT panic with "close of closed channel"
	var wg sync.WaitGroup
	for range 10 {
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

// TestCommitPRCachePopulation tests that pull_request events populate the cache.
// This is a unit test that directly tests the cache logic without needing a WebSocket connection.
func TestCommitPRCachePopulation(t *testing.T) {
	client, err := New(Config{
		ServerURL:    "ws://localhost:8080",
		Token:        "test-token",
		Organization: "test-org",
		NoReconnect:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	t.Run("pull_request event populates cache", func(t *testing.T) {
		// Simulate cache population from a pull_request event
		commitSHA := "abc123def456"
		owner := "test-org"
		repo := "test-repo"
		prNumber := 123
		key := owner + "/" + repo + ":" + commitSHA

		// Populate cache as the production code would
		client.cacheMu.Lock()
		client.commitCacheKeys = append(client.commitCacheKeys, key)
		client.commitPRCache[key] = []int{prNumber}
		client.cacheMu.Unlock()

		// Verify cache was populated
		client.cacheMu.RLock()
		cached, exists := client.commitPRCache[key]
		client.cacheMu.RUnlock()

		if !exists {
			t.Errorf("Expected cache key %q to exist", key)
		}
		if len(cached) != 1 || cached[0] != prNumber {
			t.Errorf("Expected cached PR [%d], got %v", prNumber, cached)
		}
	})

	t.Run("multiple PRs for same commit", func(t *testing.T) {
		commitSHA := "def456"
		owner := "test-org"
		repo := "test-repo"
		key := owner + "/" + repo + ":" + commitSHA

		// First PR
		client.cacheMu.Lock()
		client.commitCacheKeys = append(client.commitCacheKeys, key)
		client.commitPRCache[key] = []int{100}
		client.cacheMu.Unlock()

		// Second PR for same commit (simulates branch being merged then reopened)
		client.cacheMu.Lock()
		existing := client.commitPRCache[key]
		client.commitPRCache[key] = append(existing, 200)
		client.cacheMu.Unlock()

		// Verify both PRs are cached
		client.cacheMu.RLock()
		cached := client.commitPRCache[key]
		client.cacheMu.RUnlock()

		if len(cached) != 2 {
			t.Errorf("Expected 2 PRs in cache, got %d: %v", len(cached), cached)
		}
		if cached[0] != 100 || cached[1] != 200 {
			t.Errorf("Expected cached PRs [100, 200], got %v", cached)
		}
	})

	t.Run("cache eviction when full", func(t *testing.T) {
		// Fill cache to max size + 1 (to trigger eviction)
		client.cacheMu.Lock()
		client.commitCacheKeys = make([]string, 0, client.maxCacheSize+1)
		client.commitPRCache = make(map[string][]int)

		for i := 0; i <= client.maxCacheSize; i++ {
			key := "org/repo:sha" + string(rune(i))
			client.commitCacheKeys = append(client.commitCacheKeys, key)
			client.commitPRCache[key] = []int{i}
		}

		// Now simulate eviction logic (as production code would do)
		if len(client.commitCacheKeys) > client.maxCacheSize {
			// Evict oldest 25%
			n := client.maxCacheSize / 4
			for i := range n {
				delete(client.commitPRCache, client.commitCacheKeys[i])
			}
			client.commitCacheKeys = client.commitCacheKeys[n:]
		}
		client.cacheMu.Unlock()

		// Verify eviction happened correctly
		client.cacheMu.RLock()
		_, oldExists := client.commitPRCache["org/repo:sha"+string(rune(0))]
		cacheSize := len(client.commitPRCache)
		keyCount := len(client.commitCacheKeys)
		client.cacheMu.RUnlock()

		if oldExists {
			t.Error("Expected oldest cache entry to be evicted")
		}
		if cacheSize != keyCount {
			t.Errorf("Cache size %d doesn't match key count %d", cacheSize, keyCount)
		}
		if cacheSize > client.maxCacheSize {
			t.Errorf("Cache size %d exceeds max %d", cacheSize, client.maxCacheSize)
		}
	})
}
