// Package webhook provides HTTP handlers for processing GitHub webhook events,
// including signature validation and event extraction for broadcasting to subscribers.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sprinkler/pkg/logger"
	"github.com/codeGROOVE-dev/sprinkler/pkg/srv"
)

const maxPayloadSize = 1 << 20 // 1MB

// Handler handles GitHub webhook events.
type Handler struct {
	hub              *srv.Hub
	allowedEventsMap map[string]bool
	secret           string
	allowedEvents    []string
}

// NewHandler creates a new webhook handler.
func NewHandler(h *srv.Hub, secret string, allowedEvents []string) *Handler {
	// Build map for O(1) event type lookups
	var allowedMap map[string]bool
	if allowedEvents != nil {
		allowedMap = make(map[string]bool, len(allowedEvents))
		for _, event := range allowedEvents {
			allowedMap[event] = true
		}
	}

	return &Handler{
		hub:              h,
		secret:           secret,
		allowedEvents:    allowedEvents,
		allowedEventsMap: allowedMap,
	}
}

// ServeHTTP processes GitHub webhook events.
//
//nolint:maintidx // Webhook processing requires comprehensive validation and error handling
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Log incoming webhook request details
	logger.Info(ctx, "webhook request received", logger.Fields{
		"method":       r.Method,
		"url":          r.URL.String(),
		"remote_addr":  r.RemoteAddr,
		"user_agent":   r.UserAgent(),
		"content_type": r.Header.Get("Content-Type"),
		"event_type":   r.Header.Get("X-GitHub-Event"),    //nolint:canonicalheader // GitHub webhook header
		"delivery_id":  r.Header.Get("X-GitHub-Delivery"), //nolint:canonicalheader // GitHub webhook header
	})

	if r.Method != http.MethodPost {
		logger.Warn(ctx, "webhook rejected: invalid method", logger.Fields{
			"method":      r.Method,
			"remote_addr": r.RemoteAddr,
			"path":        r.URL.Path,
		})
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event") //nolint:canonicalheader // GitHub webhook header
	signature := r.Header.Get("X-Hub-Signature-256")
	deliveryID := r.Header.Get("X-GitHub-Delivery") //nolint:canonicalheader // GitHub webhook header

	// Check if event type is allowed
	if h.allowedEventsMap != nil && !h.allowedEventsMap[eventType] {
		logger.Warn(ctx, "webhook event type not allowed", logger.Fields{
			"event_type":  eventType,
			"delivery_id": deliveryID,
		})
		w.WriteHeader(http.StatusOK) // Still return 200 to GitHub
		return
	}

	// Check content length before reading
	if r.ContentLength > maxPayloadSize {
		logger.Warn(ctx, "webhook rejected: payload too large", logger.Fields{
			"content_length": r.ContentLength,
			"max_size":       maxPayloadSize,
			"delivery_id":    deliveryID,
			"event_type":     eventType,
		})
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPayloadSize))
	if err != nil {
		logger.Error(ctx, "error reading webhook body", err, logger.Fields{"delivery_id": deliveryID})
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Printf("failed to close request body: %v", err)
		}
	}()

	// Verify signature
	if !VerifySignature(body, signature, h.secret) {
		logger.Warn(ctx, "webhook rejected: 401 Unauthorized - signature verification failed", logger.Fields{
			"delivery_id":      deliveryID,
			"event_type":       eventType,
			"remote_addr":      r.RemoteAddr,
			"signature_exists": signature != "",
			"secret_set":       h.secret != "",
		})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse payload
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		logger.Error(ctx, "webhook rejected: 400 Bad Request - error parsing payload", err, logger.Fields{
			"delivery_id":  deliveryID,
			"event_type":   eventType,
			"remote_addr":  r.RemoteAddr,
			"payload_size": len(body),
		})
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Extract commit SHA early for check/pull_request events (used for cache and event)
	var commitSHA string
	if eventType == "check_run" || eventType == "check_suite" || eventType == "pull_request" {
		commitSHA = extractCommitSHA(eventType, payload)
	}

	// Extract PR URL
	prURL := ExtractPRURL(ctx, eventType, payload)
	if prURL == "" {
		// For non-check events, log payload and return early
		if eventType != "check_run" && eventType != "check_suite" {
			// Log full payload to understand the structure (for non-check events)
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				logger.Warn(ctx, "failed to marshal payload for logging", logger.Fields{
					"event_type":  eventType,
					"delivery_id": deliveryID,
					"error":       err.Error(),
				})
			} else {
				logger.Info(ctx, "no PR URL found in event - full payload", logger.Fields{
					"event_type":  eventType,
					"delivery_id": deliveryID,
					"payload":     string(payloadJSON),
				})
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		// For check events without PR URL, try cache lookup first
		if commitSHA != "" {
			if prInfo, found := h.hub.CommitCache().Get(ctx, commitSHA); found {
				prURL = prInfo.URL
				logger.Info(ctx, "check event: PR found via cache", logger.Fields{
					"event_type":  eventType,
					"delivery_id": deliveryID,
					"commit_sha":  truncateSHA(commitSHA),
					"pr_url":      prURL,
					"pr_number":   prInfo.Number,
				})
			}
		}

		// Fall back to repo URL if cache miss
		if prURL == "" {
			repoURL := extractRepoURL(payload)
			if repoURL == "" {
				logger.Warn(ctx, "check event: dropping - no repo URL", logger.Fields{
					"event_type":  eventType,
					"delivery_id": deliveryID,
					"commit_sha":  commitSHA,
				})
				w.WriteHeader(http.StatusOK)
				return
			}
			prURL = repoURL
			logger.Info(ctx, "check event: using repo URL (cache miss)", logger.Fields{
				"event_type":  eventType,
				"delivery_id": deliveryID,
				"commit_sha":  commitSHA,
				"repo_url":    repoURL,
			})
		}
	}

	// Create and broadcast event
	event := srv.Event{
		URL:        prURL,
		Timestamp:  time.Now(),
		Type:       eventType,
		DeliveryID: deliveryID,
		CommitSHA:  commitSHA,
	}

	// For pull_request events, cache the commit SHA → PR URL mapping
	// This enables reliable PR association for subsequent check events
	if eventType == "pull_request" {
		switch {
		case commitSHA == "":
			logger.Warn(ctx, "pull_request event: no commit SHA extracted", logger.Fields{
				"delivery_id": deliveryID,
				"pr_url":      prURL,
			})
		case !strings.Contains(prURL, "/pull/"):
			logger.Warn(ctx, "pull_request event: URL not a PR URL", logger.Fields{
				"delivery_id": deliveryID,
				"commit_sha":  truncateSHA(commitSHA),
				"url":         prURL,
			})
		default:
			// Extract PR number inline (only used here)
			var prNumber int
			if pr, ok := payload["pull_request"].(map[string]any); ok {
				if num, ok := pr["number"].(float64); ok {
					prNumber = int(num)
				}
			}
			h.hub.CommitCache().Set(ctx, commitSHA, srv.PRInfo{
				URL:     prURL,
				Number:  prNumber,
				RepoURL: extractRepoURL(payload),
			})
		}
	}

	// Get client count before broadcasting (for debugging delivery issues)
	clientCount := h.hub.ClientCount()

	h.hub.Broadcast(ctx, event, payload)

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		logger.Error(ctx, "failed to write response", err, logger.Fields{"delivery_id": deliveryID})
	}

	// Log webhook processing result
	logFields := logger.Fields{
		"event_type":        eventType,
		"delivery_id":       deliveryID,
		"url":               prURL,
		"connected_clients": clientCount,
	}

	// For check events, add context about PR association
	if eventType == "check_run" || eventType == "check_suite" {
		if strings.Contains(prURL, "/pull/") {
			logFields["pr_associated"] = true
		} else {
			logFields["pr_associated"] = false
			logFields["commit_sha"] = event.CommitSHA
		}
	}

	logger.Info(ctx, "webhook broadcast", logFields)
}

// VerifySignature validates the GitHub webhook signature.
// Uses constant-time operations to prevent timing attacks.
func VerifySignature(payload []byte, signature, secret string) bool {
	// Always compute HMAC first to maintain constant time
	// This prevents timing attacks from distinguishing between:
	// 1. Missing/empty secret
	// 2. Wrong signature format
	// 3. Invalid signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	// Perform all checks with constant-time comparison
	validFormat := strings.HasPrefix(signature, "sha256=")
	validSecret := secret != ""
	validSignature := hmac.Equal([]byte(signature), []byte(expected))

	return validFormat && validSecret && validSignature
}

// ExtractPRURL extracts the pull request URL from various event types.
func ExtractPRURL(ctx context.Context, eventType string, payload map[string]any) string {
	switch eventType {
	case "pull_request", "pull_request_review", "pull_request_review_comment":
		if pr, ok := payload["pull_request"].(map[string]any); ok {
			if htmlURL, ok := pr["html_url"].(string); ok {
				return htmlURL
			}
		}
	case "issue_comment":
		// issue_comment events can be on PRs too
		if issue, ok := payload["issue"].(map[string]any); ok {
			if _, isPR := issue["pull_request"]; isPR {
				if htmlURL, ok := issue["html_url"].(string); ok {
					return htmlURL
				}
			}
		}
	case "check_run", "check_suite":
		// Extract PR URL from check events if available in pull_requests array
		if checkRun, ok := payload["check_run"].(map[string]any); ok {
			result := extractCheckEventInfo(checkRun, payload)
			if result.prURL != "" {
				logger.Info(ctx, "check event: PR found in payload", logger.Fields{
					"event_type": eventType,
					"pr_url":     result.prURL,
					"pr_number":  result.prNumber,
					"pr_count":   result.prCount,
					"source":     result.source,
					"check_name": result.checkName,
					"conclusion": result.conclusion,
				})
				return result.prURL
			}
		}
		if checkSuite, ok := payload["check_suite"].(map[string]any); ok {
			result := extractCheckEventInfo(checkSuite, payload)
			if result.prURL != "" {
				logger.Info(ctx, "check event: PR found in payload", logger.Fields{
					"event_type": eventType,
					"pr_url":     result.prURL,
					"pr_number":  result.prNumber,
					"pr_count":   result.prCount,
					"source":     result.source,
				})
				return result.prURL
			}
		}
		// No PR URL in payload - will try cache lookup in caller
	default:
		// For other event types, no PR URL can be extracted
	}
	return ""
}

// checkEventResult contains the result of extracting PR info from a check event.
type checkEventResult struct {
	prURL      string
	source     string // How the PR URL was found: "html_url", "constructed", or ""
	commitSHA  string
	checkName  string
	conclusion string
	prNumber   int
	prCount    int // Number of PRs in the pull_requests array
}

// extractCheckEventInfo extracts PR and check info from check_run or check_suite events.
func extractCheckEventInfo(checkEvent map[string]any, payload map[string]any) checkEventResult {
	result := checkEventResult{}

	// Extract check metadata
	if name, ok := checkEvent["name"].(string); ok {
		result.checkName = name
	}
	if conclusion, ok := checkEvent["conclusion"].(string); ok {
		result.conclusion = conclusion
	}
	if sha, ok := checkEvent["head_sha"].(string); ok {
		result.commitSHA = sha
	}

	// Check for pull_requests array
	prs, ok := checkEvent["pull_requests"].([]any)
	if !ok || len(prs) == 0 {
		return result
	}
	result.prCount = len(prs)

	pr, ok := prs[0].(map[string]any)
	if !ok {
		return result
	}

	// Extract PR number
	if num, ok := pr["number"].(float64); ok {
		result.prNumber = int(num)
	}

	// Try html_url first (preferred)
	if htmlURL, ok := pr["html_url"].(string); ok {
		result.prURL = htmlURL
		result.source = "html_url"
		return result
	}

	// Fallback: construct from number + repo URL
	if result.prNumber > 0 {
		if repo, ok := payload["repository"].(map[string]any); ok {
			if repoURL, ok := repo["html_url"].(string); ok {
				result.prURL = repoURL + "/pull/" + strconv.Itoa(result.prNumber)
				result.source = "constructed"
			}
		}
	}

	return result
}

// extractCommitSHA extracts the commit SHA from pull_request, check_run, or check_suite events.
func extractCommitSHA(eventType string, payload map[string]any) string {
	switch eventType {
	case "check_run":
		if checkRun, ok := payload["check_run"].(map[string]any); ok {
			if headSHA, ok := checkRun["head_sha"].(string); ok {
				return headSHA
			}
		}
	case "check_suite":
		if checkSuite, ok := payload["check_suite"].(map[string]any); ok {
			if headSHA, ok := checkSuite["head_sha"].(string); ok {
				return headSHA
			}
		}
	case "pull_request":
		if pr, ok := payload["pull_request"].(map[string]any); ok {
			if head, ok := pr["head"].(map[string]any); ok {
				if sha, ok := head["sha"].(string); ok {
					return sha
				}
			}
		}
	default:
		// Not a supported event type for SHA extraction
	}
	return ""
}

// extractRepoURL extracts the repository HTML URL from the payload.
func extractRepoURL(payload map[string]any) string {
	if repo, ok := payload["repository"].(map[string]any); ok {
		if htmlURL, ok := repo["html_url"].(string); ok {
			return htmlURL
		}
	}
	return ""
}

// truncateSHA returns the first 8 characters of a SHA for logging.
func truncateSHA(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}
