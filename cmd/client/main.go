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

	"golang.org/x/net/websocket"
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
		serverAddr = flag.String("addr", "localhost:8080", "server address")
		org        = flag.String("org", "", "GitHub organization to subscribe to")
		token      = flag.String("token", "", "GitHub personal access token")
		myEvents   = flag.Bool("my-events", false, "Only receive events for authenticated user")
		eventTypes = flag.String("events", "", "Comma-separated list of event types to subscribe to (use '*' for all)")
		useTLS     = flag.Bool("tls", false, "Use TLS (wss://)")
		verbose    = flag.Bool("verbose", false, "Show full event details")
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

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	scheme := "ws"
	origin := "http://localhost/"
	if *useTLS {
		scheme = "wss"
		origin = "https://localhost/"
	}
	url := fmt.Sprintf("%s://%s/ws", scheme, *serverAddr)
	log.Printf("connecting to %s", url)

	config, err := websocket.NewConfig(url, origin)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Add Authorization header with Bearer token
	config.Header = make(map[string][]string)
	config.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", githubToken)}

	ws, err := websocket.DialConfig(config)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() {
		if err := ws.Close(); err != nil {
			log.Printf("failed to close websocket: %v", err)
		}
	}()

	// Send subscription
	sub := map[string]any{
		"organization":   *org,
		"my_events_only": *myEvents,
	}

	// Add event types if specified
	if *eventTypes != "" {
		// Handle special case of '*' for all events
		if *eventTypes == "*" {
			// Don't send event_types field - server will interpret as "all"
			log.Println("Subscribing to all event types")
		} else {
			types := strings.Split(*eventTypes, ",")
			for i, t := range types {
				types[i] = strings.TrimSpace(t)
			}
			sub["event_types"] = types
			log.Printf("Subscribing to event types: %v", types)
		}
	}

	if err := websocket.JSON.Send(ws, sub); err != nil {
		return fmt.Errorf("write subscription: %w", err)
	}
	log.Printf("subscribed with: %+v", sub)

	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			// Receive the full response structure
			var response map[string]any
			if err := websocket.JSON.Receive(ws, &response); err != nil {
				log.Println("read:", err)
				return
			}

			// Extract common fields if they exist
			timestamp := ""
			if ts, ok := response["timestamp"].(string); ok {
				// Parse and format timestamp
				if t, err := time.Parse(time.RFC3339, ts); err == nil {
					timestamp = t.Format("15:04:05")
				} else {
					timestamp = ts
				}
			}

			eventType := ""
			if et, ok := response["type"].(string); ok {
				eventType = et
			}

			url := ""
			if u, ok := response["url"].(string); ok {
				url = u
			}

			// Display based on verbosity
			if *verbose {
				// Pretty print the full JSON response
				fmt.Printf("\n=== Event at %s ===\n", timestamp)
				fmt.Printf("Type: %s\n", eventType)
				fmt.Printf("URL: %s\n", url)
				fmt.Println("Full response:")
				prettyPrintJSON(response)
				fmt.Println()
			} else {
				// Compact single-line format
				if eventType != "" && url != "" {
					fmt.Printf("[%s] %s: %s\n", timestamp, eventType, url)
				} else {
					// Fallback to showing whatever we received
					fmt.Printf("[%s] Event received: %v\n", timestamp, response)
				}
			}
		}
	}()

	for {
		select {
		case <-done:
			return nil
		case <-interrupt:
			log.Println("interrupt")
			return nil
		}
	}
}

// prettyPrintJSON prints a JSON object in a formatted, indented way.
func prettyPrintJSON(data map[string]any) {
	jsonBytes, err := json.MarshalIndent(data, "  ", "  ")
	if err != nil {
		// Fallback to simple print if marshaling fails
		fmt.Printf("  %v\n", data)
		return
	}
	fmt.Printf("  %s\n", string(jsonBytes))
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
