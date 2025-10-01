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
)

const maxPayloadSize = 1 << 20 // 1MB

// Handler handles GitHub webhook events.
type Handler struct {
	hub              *hub.Hub
	allowedEventsMap map[string]bool
	secret           string
	allowedEvents    []string
}

// NewHandler creates a new webhook handler.
func NewHandler(h *hub.Hub, secret string, allowedEvents []string) *Handler {
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
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Log incoming webhook request details
	logger.Info("webhook request received", logger.Fields{
		"method":       r.Method,
		"url":          r.URL.String(),
		"remote_addr":  r.RemoteAddr,
		"user_agent":   r.UserAgent(),
		"content_type": r.Header.Get("Content-Type"),
		"event_type":   r.Header.Get("X-GitHub-Event"),    //nolint:canonicalheader // GitHub webhook header
		"delivery_id":  r.Header.Get("X-GitHub-Delivery"), //nolint:canonicalheader // GitHub webhook header
	})

	if r.Method != http.MethodPost {
		logger.Warn("webhook rejected: invalid method", logger.Fields{
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
		logger.Warn("webhook event type not allowed", logger.Fields{
			"event_type":  eventType,
			"delivery_id": deliveryID,
		})
		w.WriteHeader(http.StatusOK) // Still return 200 to GitHub
		return
	}

	// Check content length before reading
	if r.ContentLength > maxPayloadSize {
		logger.Warn("webhook rejected: payload too large", logger.Fields{
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
		logger.Warn("webhook rejected: 401 Unauthorized - signature verification failed", logger.Fields{
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
		logger.Error("webhook rejected: 400 Bad Request - error parsing payload", err, logger.Fields{
			"delivery_id":  deliveryID,
			"event_type":   eventType,
			"remote_addr":  r.RemoteAddr,
			"payload_size": len(body),
		})
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Extract PR URL
	prURL := ExtractPRURL(eventType, payload)
	if prURL == "" {
		// Log full payload to understand the structure
		payloadJSON, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			logger.Warn("failed to marshal payload for logging", logger.Fields{
				"event_type":  eventType,
				"delivery_id": deliveryID,
				"error":       err.Error(),
			})
		} else {
			logger.Info("no PR URL found in event - full payload", logger.Fields{
				"event_type":  eventType,
				"delivery_id": deliveryID,
				"payload":     string(payloadJSON),
			})
		}
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

	// Log successful webhook processing
	logger.Info("webhook processed successfully", logger.Fields{
		"event_type":   eventType,
		"delivery_id":  deliveryID,
		"pr_url":       prURL,
		"remote_addr":  r.RemoteAddr,
		"payload_size": len(body),
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
