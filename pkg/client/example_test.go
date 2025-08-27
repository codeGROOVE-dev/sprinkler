package client_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/codeGROOVE-dev/sprinkler/pkg/client"
)

func ExampleClient() {
	// Create client configuration
	config := client.Config{
		ServerURL:    "wss://hook.example.com/ws",
		Organization: "myorg",
		Token:        "ghp_yourtoken",
		EventTypes:   []string{"pull_request", "issue_comment"},
		UserEventsOnly: true,
		Verbose:      false,
		MaxRetries:   5,
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
		log.Fatal(err)
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
		Organization: "myorg",
		Token:        "ghp_yourtoken",
	}

	c, err := client.New(config)
	if err != nil {
		log.Fatal(err)
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
