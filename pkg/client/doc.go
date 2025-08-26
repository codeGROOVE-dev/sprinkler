// Package client provides a robust WebSocket client for webhook sprinkler servers.
//
// The client handles:
//   - Automatic reconnection with exponential backoff
//   - Ping/pong keep-alive messages
//   - Comprehensive logging of connection states
//   - Event callbacks for custom processing
//   - Graceful shutdown
//
// Basic usage:
//
//	config := client.Config{
//	    ServerURL:    "wss://example.com/ws",
//	    Organization: "myorg",
//	    Token:        "ghp_...",
//	    OnEvent: func(event client.Event) {
//	        fmt.Printf("Got event: %s\n", event.Type)
//	    },
//	}
//
//	c, err := client.New(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	ctx := context.Background()
//	if err := c.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
package client
