# webhook-sprinkler

<div align="center">
  <img src="media/logo-small.png" alt="webhook-sprinkler logo" width="300">
</div>

GitHub only allows one webhook endpoint per app. This service multiplexes that single webhook into authenticated WebSocket connections, so multiple clients can subscribe to just the events they care about.

## Quick start

```bash
export GITHUB_WEBHOOK_SECRET="your-webhook-secret"
go run ./cmd/server
go run ./cmd/client
```

## Client example

```javascript
const ws = new WebSocket('wss://your-server/ws', {
  headers: { 'Authorization': 'Bearer ghp_your_github_token' }
});

ws.on('open', () => {
  ws.send(JSON.stringify({
    organization: "your-org",
    event_types: ["pull_request"],
    my_events_only: false
  }));
});

ws.on('message', (data) => {
  const event = JSON.parse(data);
  console.log(`${event.type}: ${event.url}`);
});
```

## Configuration

```bash
-webhook-secret="..."        # GitHub webhook secret (required)
-allowed-events="..."        # Event types to allow or "*" for all
-rate-limit=100              # Requests per minute per IP
-max-conns-per-ip=10         # WebSocket connections per IP
-max-conns-total=1000        # Total WebSocket connections
-letsencrypt                 # Auto HTTPS via Let's Encrypt
-le-domains="..."            # Your domain(s)
```

## How it works

1. GitHub sends webhook to this service
2. Service verifies HMAC signature
3. Broadcasts event to WebSocket clients that:
   - Have valid GitHub tokens
   - Are members of the event's organization
   - Have subscribed to that event type

## Development

```bash
make test       # Run tests
make fmt        # Format code
make lint       # Run linter
```
