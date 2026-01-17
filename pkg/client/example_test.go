package client_test

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/codeGROOVE-dev/sprinkler/pkg/client"
)

func ExampleClient() {
	// Create client configuration
	config := client.Config{
		ServerURL:      "wss://hook.example.com/ws",
		UserAgent:      "myapp/v1.0.0", // Required: client name and version
		Organization:   "myorg",
		Token:          "ghp_yourtoken",
		EventTypes:     []string{"pull_request", "issue_comment"},
		UserEventsOnly: true,
		Verbose:        false,
		MaxRetries:     5,
		OnEvent: func(event client.Event) {
			// Process each event
			fmt.Printf("Event: %s at %s\n", event.Type, event.URL)
		},
		OnConnect: func() {
			log.Println("Connected successfully!")
		},
		OnDisconnect: func(err error) {
			log.Printf("Disconnected: %v", err)
		},
	}

	// Create the client
	c, err := client.New(config)
	if err != nil {
		log.Print(err)
		return
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Start the client (blocks until error or context cancellation)
	if err := c.Start(ctx); err != nil {
		log.Printf("Client stopped: %v", err)
	}
}

func ExampleClient_gracefulShutdown() {
	config := client.Config{
		ServerURL:    "wss://hook.example.com/ws",
		UserAgent:    "myapp/v1.0.0",
		Organization: "myorg",
		Token:        "ghp_yourtoken",
	}

	c, err := client.New(config)
	if err != nil {
		log.Print(err)
		return
	}

	// Start client in goroutine
	ctx := context.Background()
	go func() {
		if err := c.Start(ctx); err != nil {
			log.Printf("Client error: %v", err)
		}
	}()

	// Do some work...
	time.Sleep(10 * time.Second)

	// Gracefully stop the client
	c.Stop()
}

func ExampleClient_customLogger() {
	// Example 1: Silence all logs
	silentLogger := slog.New(slog.DiscardHandler)

	// Example 2: JSON logging to a file
	logFile, err := os.Create("client.log")
	if err == nil {
		defer func() {
			if err := logFile.Close(); err != nil {
				log.Printf("Failed to close log file: %v", err)
			}
		}()
	}
	var jsonLogger *slog.Logger
	if logFile != nil {
		jsonLogger = slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}

	// Example 3: Structured logging with custom format
	structuredLogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Use the silent logger for a client that produces no output
	config := client.Config{
		ServerURL:    "wss://hook.example.com/ws",
		Organization: "myorg",
		Token:        "ghp_yourtoken",
		Logger:       silentLogger, // No log output
	}

	c, err := client.New(config)
	if err != nil {
		log.Print(err)
		return
	}

	// Alternative: use the JSON logger
	if jsonLogger != nil {
		config.Logger = jsonLogger
		c2, err := client.New(config)
		if err != nil {
			log.Print(err)
			return
		}
		_ = c2
	}

	// Alternative: use structured text logger
	config.Logger = structuredLogger
	c3, err := client.New(config)
	if err != nil {
		log.Print(err)
		return
	}

	_ = c
	_ = c3
}
