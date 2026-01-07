package srv

import (
	"context"
	"testing"
	"time"
)

func TestCommitCache_SetAndGet(t *testing.T) {
	ctx := context.Background()
	cache := NewCommitCache()

	// Test setting and getting a value
	info := PRInfo{
		URL:     "https://github.com/owner/repo/pull/123",
		Number:  123,
		RepoURL: "https://github.com/owner/repo",
	}
	cache.Set(ctx, "abc123def456", info)

	// Verify we can get it back
	got, found := cache.Get(ctx, "abc123def456")
	if !found {
		t.Fatal("expected to find cached entry")
	}
	if got.URL != info.URL {
		t.Errorf("URL mismatch: got %q, want %q", got.URL, info.URL)
	}
	if got.Number != info.Number {
		t.Errorf("Number mismatch: got %d, want %d", got.Number, info.Number)
	}
	if got.RepoURL != info.RepoURL {
		t.Errorf("RepoURL mismatch: got %q, want %q", got.RepoURL, info.RepoURL)
	}
	if got.CachedAt.IsZero() {
		t.Error("CachedAt should be set")
	}
}

func TestCommitCache_Miss(t *testing.T) {
	ctx := context.Background()
	cache := NewCommitCache()

	// Test cache miss
	_, found := cache.Get(ctx, "nonexistent123")
	if found {
		t.Error("expected cache miss for nonexistent key")
	}
}

func TestCommitCache_EmptyKey(t *testing.T) {
	ctx := context.Background()
	cache := NewCommitCache()

	// Empty key should not be cached
	cache.Set(ctx, "", PRInfo{URL: "https://example.com"})
	if cache.Len() != 0 {
		t.Error("empty key should not be cached")
	}

	// Empty key lookup should return not found
	_, found := cache.Get(ctx, "")
	if found {
		t.Error("empty key lookup should return not found")
	}
}

func TestCommitCache_EmptyURL(t *testing.T) {
	ctx := context.Background()
	cache := NewCommitCache()

	// Empty URL should not be cached
	cache.Set(ctx, "abc123", PRInfo{URL: ""})
	if cache.Len() != 0 {
		t.Error("empty URL should not be cached")
	}
}

func TestCommitCache_Overwrite(t *testing.T) {
	ctx := context.Background()
	cache := NewCommitCache()

	// Set initial value
	cache.Set(ctx, "abc123", PRInfo{
		URL:    "https://github.com/owner/repo/pull/1",
		Number: 1,
	})

	// Overwrite with new value
	cache.Set(ctx, "abc123", PRInfo{
		URL:    "https://github.com/owner/repo/pull/2",
		Number: 2,
	})

	// Should get the new value
	got, found := cache.Get(ctx, "abc123")
	if !found {
		t.Fatal("expected to find cached entry")
	}
	if got.Number != 2 {
		t.Errorf("expected PR #2, got #%d", got.Number)
	}
}

func TestCommitCache_MultipleEntries(t *testing.T) {
	ctx := context.Background()
	cache := NewCommitCache()

	// Add multiple entries
	for i := 1; i <= 100; i++ {
		cache.Set(ctx, "sha"+string(rune(i)), PRInfo{
			URL:    "https://github.com/owner/repo/pull/" + string(rune(i)),
			Number: i,
		})
	}

	if cache.Len() != 100 {
		t.Errorf("expected 100 entries, got %d", cache.Len())
	}
}

func TestTruncateSHA(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"abc123def456", "abc123de"},
		{"short", "short"},
		{"exactly8", "exactly8"},
		{"", ""},
	}

	for _, tt := range tests {
		got := truncateSHA(tt.input)
		if got != tt.want {
			t.Errorf("truncateSHA(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCommitCache_CachedAtSet(t *testing.T) {
	ctx := context.Background()
	cache := NewCommitCache()

	before := time.Now()
	cache.Set(ctx, "abc123", PRInfo{
		URL:    "https://github.com/owner/repo/pull/1",
		Number: 1,
	})
	after := time.Now()

	got, found := cache.Get(ctx, "abc123")
	if !found {
		t.Fatal("expected to find cached entry")
	}

	if got.CachedAt.Before(before) || got.CachedAt.After(after) {
		t.Errorf("CachedAt %v not between %v and %v", got.CachedAt, before, after)
	}
}
