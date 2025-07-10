# githooksock

A lightweight GitHub webhook listener that provides real-time WebSocket subscriptions for pull request events.

> **⚠️ IMPORTANT SECURITY NOTE**: This utility does not authenticate WebSocket clients. Any client that can connect to the WebSocket endpoint can subscribe to events from any repository configured to send webhooks to this service. Only deploy this service in trusted environments or implement additional authentication if handling sensitive repository data.

## Features

- Receives GitHub webhook events for pull requests and related activities
- WebSocket API for clients to subscribe based on username, PR URL, or repository
- HMAC-SHA256 webhook signature verification
- Rate limiting and connection limits for DoS protection
- Input validation for all subscription data
- TLS support via Let's Encrypt for secure connections
- Minimal dependencies (only `golang.org/x/net` and `golang.org/x/crypto`)
- Privacy-focused: Minimal logging of sensitive data

## Usage

### Running the server

```bash
# Basic usage with webhook secret
GITHUB_WEBHOOK_SECRET=your-secret go run .

# Production with Let's Encrypt
go run . \
  -webhook-secret=your-secret \
  -letsencrypt \
  -le-domains=example.com \
  -le-email=admin@example.com
```

### Command-line flags

- `-webhook-secret`: GitHub webhook secret for signature verification (or set `GITHUB_WEBHOOK_SECRET` env var)
- `-addr`: HTTP service address (default: `:8080`, ignored when using Let's Encrypt)
- `-letsencrypt`: Enable Let's Encrypt automatic TLS certificates
- `-le-domains`: Comma-separated list of domains for Let's Encrypt (required with `-letsencrypt`)
- `-le-email`: Contact email for Let's Encrypt notifications (optional but recommended)
- `-le-cache-dir`: Cache directory for Let's Encrypt certificates (default: `./.letsencrypt`)
- `-max-conns-per-ip`: Maximum WebSocket connections per IP (default: 10)
- `-max-conns-total`: Maximum total WebSocket connections (default: 1000)
- `-rate-limit`: Maximum requests per minute per IP (default: 100)

### Webhook Configuration

Configure your GitHub webhook to send events to:
- `http://your-server:8080/webhook` (when using HTTP)
- `https://your-domain.com/webhook` (when using Let's Encrypt)

Select these events:
- Pull requests
- Pull request reviews
- Pull request review comments
- Issue comments
- Check runs
- Check suites

### WebSocket Client

Connect to `ws://your-server:8080/ws` (or `wss://` for TLS) and send a subscription:

```json
{
  "username": "alice",
  "pr_url": "https://github.com/owner/repo/pull/123",
  "repository": "https://github.com/owner/repo"
}
```

You'll receive events matching any of your subscription criteria:

```json
{
  "url": "https://github.com/owner/repo/pull/123",
  "timestamp": "2024-01-15T10:30:00Z",
  "type": "pull_request"
}
```

## Security Best Practices

1. **Always use a webhook secret** - Required for authenticating GitHub webhooks
2. **Enable TLS in production** - Use `-letsencrypt` for automatic certificates
3. **Configure rate limits** - Adjust based on your expected traffic
4. **Restrict network access** - Use firewall rules to limit who can connect
5. **Monitor connections** - Watch for unusual patterns or high connection counts

## Let's Encrypt Usage

When using Let's Encrypt (`-letsencrypt` flag):
- Domains must be publicly accessible
- Port 80 must be available for ACME challenges
- Port 443 will be used for HTTPS
- Certificates auto-renew before expiration
- First run may take 10-30 seconds to obtain certificates

## Testing

```bash
go test ./...
```

## Example Client

See `example_client.go` for a complete WebSocket client implementation.