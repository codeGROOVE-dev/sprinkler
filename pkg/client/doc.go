// Package client provides a robust WebSocket client for webhook sprinkler servers.
//
// The client handles:
//   - Automatic reconnection with exponential backoff
//   - Ping/pong keep-alive messages
//   - Structured logging with customizable output
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
//
// To disable logging or customize output:
//
//	import "log/slog"
//	import "io"
//
//	// Silence all logs
//	config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
//
//	// Or use JSON logging
//	config.Logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
package client
