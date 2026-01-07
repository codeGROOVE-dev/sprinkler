// Package srv provides a WebSocket hub for managing client connections and broadcasting
// GitHub webhook events to subscribed clients based on their subscription criteria.
package srv

import (
	"context"
	"time"

	"github.com/codeGROOVE-dev/fido"
	"github.com/codeGROOVE-dev/sprinkler/pkg/logger"
)

const (
	// commitCacheSize is the maximum number of commit→PR mappings to cache.
	// 16K entries should be sufficient for most deployments.
	commitCacheSize = 16384

	// commitCacheTTL is how long to keep commit→PR mappings.
	// 24 hours is sufficient since PRs are typically merged or closed within that time.
	commitCacheTTL = 24 * time.Hour
)

// PRInfo contains cached information about a pull request.
type PRInfo struct {
	URL      string // Full PR URL (e.g., https://github.com/owner/repo/pull/123)
	Number   int    // PR number
	RepoURL  string // Repository URL (e.g., https://github.com/owner/repo)
	CachedAt time.Time
}

// CommitCache maps commit SHAs to their associated pull requests.
// This enables reliable PR association for check_run/check_suite events
// even when GitHub's pull_requests array is empty.
type CommitCache struct {
	cache *fido.Cache[string, PRInfo]
}

// NewCommitCache creates a new commit→PR cache.
func NewCommitCache() *CommitCache {
	return &CommitCache{
		cache: fido.New[string, PRInfo](
			fido.Size(commitCacheSize),
			fido.TTL(commitCacheTTL),
		),
	}
}

// Set caches a commit SHA → PR mapping.
func (c *CommitCache) Set(ctx context.Context, commitSHA string, info PRInfo) {
	if commitSHA == "" || info.URL == "" {
		return
	}

	info.CachedAt = time.Now()
	c.cache.Set(commitSHA, info)

	logger.Info(ctx, "commit cache: stored PR mapping", logger.Fields{
		"commit_sha": truncateSHA(commitSHA),
		"pr_url":     info.URL,
		"pr_number":  info.Number,
		"cache_size": c.cache.Len(),
	})
}

// Get retrieves PR info for a commit SHA.
// Returns the PRInfo and true if found, or zero value and false if not cached.
func (c *CommitCache) Get(ctx context.Context, commitSHA string) (PRInfo, bool) {
	if commitSHA == "" {
		return PRInfo{}, false
	}

	info, found := c.cache.Get(commitSHA)
	if found {
		logger.Info(ctx, "commit cache: HIT", logger.Fields{
			"commit_sha": truncateSHA(commitSHA),
			"pr_url":     info.URL,
			"pr_number":  info.Number,
			"cached_ago": time.Since(info.CachedAt).Round(time.Second).String(),
		})
	} else {
		logger.Info(ctx, "commit cache: MISS", logger.Fields{
			"commit_sha": truncateSHA(commitSHA),
			"cache_size": c.cache.Len(),
		})
	}

	return info, found
}

// Len returns the number of cached entries.
func (c *CommitCache) Len() int {
	return c.cache.Len()
}

// truncateSHA returns the first 8 characters of a SHA for logging.
func truncateSHA(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}
