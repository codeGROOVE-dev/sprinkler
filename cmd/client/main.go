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
	"syscall"
	"time"

	"github.com/codeGROOVE-dev/sprinkler/pkg/client"
)

func run() error {
	var (
		serverAddr  = flag.String("addr", client.DefaultServerAddress, "server address (hostname:port)")
		org         = flag.String("org", "", "GitHub organization to subscribe to (use '*' for all your orgs)")
		token       = flag.String("token", "", "GitHub personal access token")
		userEvents  = flag.Bool("user", false, "Subscribe to your events across all organizations")
		eventTypes  = flag.String("events", "", "Comma-separated list of event types to subscribe to (use '*' for all)")
		prs         = flag.String("prs", "", "Comma-separated list of PR URLs to subscribe to (max 200)")
		insecure    = flag.Bool("insecure", false, "Use insecure WebSocket (ws:// instead of wss://)")
		verbose     = flag.Bool("verbose", false, "Show full event details")
		noReconnect = flag.Bool("no-reconnect", false, "Disable automatic reconnection")
		maxRetries  = flag.Int("max-retries", 0, "Maximum reconnection attempts (0 = infinite)")
		outputJSON  = flag.Bool("json", false, "Output events as JSON")
	)
	flag.Parse()

	// Parse PR URLs
	var prList []string
	if *prs != "" {
		urls := strings.Split(*prs, ",")
		for i, url := range urls {
			urls[i] = strings.TrimSpace(url)
		}
		prList = urls
		log.Printf("Subscribing to %d specific PRs", len(prList))
	}

	// Handle --user mode
	if *userEvents {
		log.Println("User mode enabled: subscribing to your events across all organizations")
	}

	// If no org is specified and not using PR-only mode, default to '*' (all orgs)
	if *org == "" && len(prList) == 0 {
		*org = "*"
		log.Println("No organization specified, subscribing to all your organizations")
	}

	// Validate that we have at least one subscription type
	if *org == "" && len(prList) == 0 {
		return errors.New("organization, PR URLs, or --user flag required")
	}

	// Get token from various sources: flag, environment variable, or gh CLI
	var githubToken string
	var err error
	if *token != "" {
		githubToken = *token
	} else if envToken := os.Getenv("GITHUB_TOKEN"); envToken != "" {
		log.Println("Using token from GITHUB_TOKEN environment variable")
		githubToken = envToken
	} else {
		log.Println("No token provided, attempting to use gh auth token")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "gh", "auth", "token")
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to get token from 'gh auth token': %w\n"+
				"Please provide a token via -token flag, GITHUB_TOKEN env var, or authenticate with 'gh auth login'", err)
		}
		githubToken = strings.TrimSpace(string(output))
		if githubToken == "" {
			return errors.New("gh auth token returned empty token")
		}
		log.Println("Using token from gh auth token")
	}

	// Build WebSocket URL - secure by default
	scheme := "wss"
	if *insecure {
		scheme = "ws"
		log.Println("WARNING: Using insecure WebSocket connection (ws://)")
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
		ServerURL:      url,
		UserAgent:      fmt.Sprintf("sprinkler-cli/%s", client.Version),
		Organization:   *org,
		Token:          githubToken,
		EventTypes:     eventTypesList,
		PullRequests:   prList,
		UserEventsOnly: *userEvents,
		Verbose:        *verbose,
		NoReconnect:    *noReconnect,
		MaxRetries:     *maxRetries,
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
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	log.Println("Signal handler set up, press Ctrl+C to stop")

	// Start client in goroutine so we can handle signals
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx)
	}()

	// Wait for either client error or interrupt signal
	select {
	case err := <-errCh:
		return err
	case sig := <-interrupt:
		log.Printf("Signal %v received, shutting down gracefully...", sig)
		c.Stop() // Properly close WebSocket connection
		cancel()

		// Wait for client to finish with timeout
		select {
		case <-errCh:
			return nil // Client shut down gracefully
		case <-time.After(5 * time.Second):
			log.Println("Shutdown timeout exceeded, forcing exit")
			return nil
		}
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
