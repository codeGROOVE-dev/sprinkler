/*
Package main implements githooksock, a GitHub webhook listener that provides
WebSocket subscriptions for pull request events.

githooksock acts as a bridge between GitHub webhooks and WebSocket clients,
allowing real-time notifications of pull request activity. Clients can subscribe
to events based on:
  - GitHub username (as author, assignee, reviewer, or mentioned)
  - Specific pull request URL
  - Repository URL

Security features include:
  - HMAC-SHA256 webhook signature verification
  - Rate limiting per IP address
  - Connection limits (per-IP and total)
  - Input validation for all subscription data
  - TLS support via Let's Encrypt

Usage:

	githooksock -webhook-secret=secret -letsencrypt -le-domains=example.com

The server exposes two endpoints:
  - /webhook - Receives GitHub webhook events
  - /ws - WebSocket endpoint for client subscriptions

Clients connect to the WebSocket endpoint and send a JSON subscription:

	{
	  "username": "alice",
	  "pr_url": "https://github.com/owner/repo/pull/123",
	  "repository": "https://github.com/owner/repo"
	}

They will then receive matching events:

	{
	  "url": "https://github.com/owner/repo/pull/123",
	  "timestamp": "2024-01-15T10:30:00Z",
	  "type": "pull_request"
	}

Note: WebSocket clients are not authenticated. Deploy only in trusted environments
or implement additional authentication if handling sensitive repository data.
*/
package main