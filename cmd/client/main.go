// Package main provides a command-line client for subscribing to GitHub webhook events
// via WebSocket connections to a webhook sprinkler server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sprinkler/pkg/client"
)

// getGitHubToken attempts to get a GitHub token from multiple sources:
// 1. Command-line flag
// 2. GITHUB_TOKEN environment variable
// 3. gh auth token command.
func getGitHubToken(flagToken string) (string, error) {
	// First try flag
	if flagToken != "" {
		return flagToken, nil
	}

	// Then try environment variable
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		log.Println("Using token from GITHUB_TOKEN environment variable")
		return token, nil
	}

	// Finally try gh auth token
	log.Println("No token provided, attempting to use gh auth token")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gh", "auth", "token")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get token from 'gh auth token': %w\n"+
			"Please provide a token via -token flag, GITHUB_TOKEN env var, or authenticate with 'gh auth login'", err)
	}

	token := strings.TrimSpace(string(output))
	if token == "" {
		return "", errors.New("gh auth token returned empty token")
	}

	log.Println("Using token from gh auth token")
	return token, nil
}

func run() error {
	var (
		serverAddr  = flag.String("addr", "localhost:8080", "server address")
		org         = flag.String("org", "", "GitHub organization to subscribe to")
		token       = flag.String("token", "", "GitHub personal access token")
		myEvents    = flag.Bool("my-events", false, "Only receive events for authenticated user")
		eventTypes  = flag.String("events", "", "Comma-separated list of event types to subscribe to (use '*' for all)")
		useTLS      = flag.Bool("tls", false, "Use TLS (wss://)")
		verbose     = flag.Bool("verbose", false, "Show full event details")
		noReconnect = flag.Bool("no-reconnect", false, "Disable automatic reconnection")
		maxRetries  = flag.Int("max-retries", 0, "Maximum reconnection attempts (0 = infinite)")
		outputJSON  = flag.Bool("json", false, "Output events as JSON")
	)
	flag.Parse()

	if *org == "" {
		return errors.New("organization required: -org")
	}

	// Get token from various sources
	githubToken, err := getGitHubToken(*token)
	if err != nil {
		return err
	}

	// Build WebSocket URL
	scheme := "ws"
	if *useTLS {
		scheme = "wss"
	}
	url := fmt.Sprintf("%s://%s/ws", scheme, *serverAddr)

	// Parse event types
	var eventTypesList []string
	if *eventTypes != "" {
		if *eventTypes == "*" {
			eventTypesList = []string{"*"}
		} else {
			types := strings.Split(*eventTypes, ",")
			for i, t := range types {
				types[i] = strings.TrimSpace(t)
			}
			eventTypesList = types
		}
	}

	// Create client configuration
	config := client.Config{
		ServerURL:    url,
		Organization: *org,
		Token:        githubToken,
		EventTypes:   eventTypesList,
		MyEventsOnly: *myEvents,
		Verbose:      *verbose,
		NoReconnect:  *noReconnect,
		MaxRetries:   *maxRetries,
		OnEvent: func(event client.Event) {
			// Custom event handling for the CLI
			if *outputJSON {
				// Output as JSON for machine parsing
				jsonBytes, err := json.Marshal(event.Raw)
				if err != nil {
					log.Printf("Failed to marshal event to JSON: %v", err)
					return
				}
				fmt.Println(string(jsonBytes))
			}
			// The client package already logs events in non-JSON mode
		},
	}

	// Create the client
	c, err := client.New(config)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	go func() {
		<-interrupt
		log.Println("Interrupt received, shutting down gracefully...")
		cancel()
	}()

	// Start the client
	return c.Start(ctx)
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
