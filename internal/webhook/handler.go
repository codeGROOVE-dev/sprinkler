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

	"github.com/ready-to-review/github-event-socket/internal/hub"
)

const maxPayloadSize = 1 << 20 // 1MB

// Handler handles GitHub webhook events.
type Handler struct {
	hub    *hub.Hub
	secret string
}

// NewHandler creates a new webhook handler.
func NewHandler(h *hub.Hub, secret string) *Handler {
	return &Handler{
		hub:    h,
		secret: secret,
	}
}

// ServeHTTP processes GitHub webhook events.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event")
	signature := r.Header.Get("X-Hub-Signature-256")
	deliveryID := r.Header.Get("X-GitHub-Delivery")
	

	// Check content length before reading
	if r.ContentLength > maxPayloadSize {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	
	// Read body
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPayloadSize))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Verify signature
	if !VerifySignature(body, signature, h.secret) {
				log.Printf("webhook signature verification failed for delivery: %s", deliveryID)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse payload
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
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
	w.Write([]byte("OK"))
	log.Printf("processed webhook: event=%s delivery=%s", eventType, deliveryID)
}

// VerifySignature validates the GitHub webhook signature.
func VerifySignature(payload []byte, signature, secret string) bool {
	if secret == "" {
		return true // Skip verification if no secret configured
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
func ExtractPRURL(eventType string, payload map[string]interface{}) string {
	switch eventType {
	case "pull_request", "pull_request_review", "pull_request_review_comment":
		if pr, ok := payload["pull_request"].(map[string]interface{}); ok {
			if htmlURL, ok := pr["html_url"].(string); ok {
				return htmlURL
			}
		}
	case "issue_comment":
		// issue_comment events can be on PRs too
		if issue, ok := payload["issue"].(map[string]interface{}); ok {
			if _, isPR := issue["pull_request"]; isPR {
				if htmlURL, ok := issue["html_url"].(string); ok {
					return htmlURL
				}
			}
		}
	case "check_run", "check_suite":
		// Extract PR URLs from check events if available
		if checkRun, ok := payload["check_run"].(map[string]interface{}); ok {
			if prs, ok := checkRun["pull_requests"].([]interface{}); ok && len(prs) > 0 {
				if pr, ok := prs[0].(map[string]interface{}); ok {
					if htmlURL, ok := pr["html_url"].(string); ok {
						return htmlURL
					}
				}
			}
		}
		if checkSuite, ok := payload["check_suite"].(map[string]interface{}); ok {
			if prs, ok := checkSuite["pull_requests"].([]interface{}); ok && len(prs) > 0 {
				if pr, ok := prs[0].(map[string]interface{}); ok {
					if htmlURL, ok := pr["html_url"].(string); ok {
						return htmlURL
					}
				}
			}
		}
	}
	return ""
}