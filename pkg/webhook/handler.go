// Package webhook provides HTTP handlers for processing GitHub webhook events,
// including signature validation and event extraction for broadcasting to subscribers.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sprinkler/pkg/hub"
	"github.com/codeGROOVE-dev/sprinkler/pkg/logger"
	"github.com/codeGROOVE-dev/sprinkler/pkg/security"
)

const maxPayloadSize = 1 << 20 // 1MB

// Handler handles GitHub webhook events.
type Handler struct {
	ipValidator      IPValidator
	hub              *hub.Hub
	allowedEventsMap map[string]bool
	secret           string
	allowedEvents    []string
}

// IPValidator interface for IP validation.
type IPValidator interface {
	IsValid(ip string) bool
}

// NewHandler creates a new webhook handler.
func NewHandler(h *hub.Hub, secret string, allowedEvents []string, ipValidator IPValidator) *Handler {
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
		ipValidator:      ipValidator,
	}
}

// ServeHTTP processes GitHub webhook events.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate source IP if validator is configured
	if h.ipValidator != nil {
		// Use secure IP extraction from security package
		clientIP := security.ClientIP(r)
		if !h.ipValidator.IsValid(clientIP) {
			logger.Warn("webhook rejected from non-GitHub IP", logger.Fields{"ip": clientIP})
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	eventType := r.Header.Get("X-GitHub-Event") //nolint:canonicalheader // GitHub webhook header
	signature := r.Header.Get("X-Hub-Signature-256")
	deliveryID := r.Header.Get("X-GitHub-Delivery") //nolint:canonicalheader // GitHub webhook header

	// Check if event type is allowed
	if h.allowedEventsMap != nil && !h.allowedEventsMap[eventType] {
		logger.Warn("webhook event type not allowed", logger.Fields{
			"event_type":  eventType,
			"delivery_id": deliveryID,
		})
		w.WriteHeader(http.StatusOK) // Still return 200 to GitHub
		return
	}

	// Check content length before reading
	if r.ContentLength > maxPayloadSize {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPayloadSize))
	if err != nil {
		logger.Error("error reading webhook body", err, logger.Fields{"delivery_id": deliveryID})
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
		logger.Warn("webhook signature verification failed", logger.Fields{"delivery_id": deliveryID})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse payload
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		logger.Error("error parsing webhook payload", err, logger.Fields{"delivery_id": deliveryID})
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Extract PR URL
	prURL := ExtractPRURL(eventType, payload)
	if prURL == "" {
		log.Printf("no PR URL found in %s event", eventType)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Create and broadcast event
	event := hub.Event{
		URL:       prURL,
		Timestamp: time.Now(),
		Type:      eventType,
	}

	h.hub.Broadcast(event, payload)

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		logger.Error("failed to write response", err, logger.Fields{"delivery_id": deliveryID})
	}
	logger.Info("processed webhook", logger.Fields{
		"event_type":  eventType,
		"delivery_id": deliveryID,
		"pr_url":      prURL,
	})
}

// VerifySignature validates the GitHub webhook signature.
func VerifySignature(payload []byte, signature, secret string) bool {
	// Secret is required for security - no bypass allowed
	if secret == "" {
		return false
	}

	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expected))
}

// ExtractPRURL extracts the pull request URL from various event types.
func ExtractPRURL(eventType string, payload map[string]any) string {
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
		// Extract PR URLs from check events if available
		if checkRun, ok := payload["check_run"].(map[string]any); ok {
			if prs, ok := checkRun["pull_requests"].([]any); ok && len(prs) > 0 {
				if pr, ok := prs[0].(map[string]any); ok {
					if htmlURL, ok := pr["html_url"].(string); ok {
						return htmlURL
					}
				}
			}
		}
		if checkSuite, ok := payload["check_suite"].(map[string]any); ok {
			if prs, ok := checkSuite["pull_requests"].([]any); ok && len(prs) > 0 {
				if pr, ok := prs[0].(map[string]any); ok {
					if htmlURL, ok := pr["html_url"].(string); ok {
						return htmlURL
					}
				}
			}
		}
	default:
		// For other event types, no PR URL can be extracted
	}
	return ""
}
