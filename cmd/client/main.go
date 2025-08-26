// Package main provides a command-line client for subscribing to GitHub webhook events
// via WebSocket connections to a webhook sprinkler server.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

func run() error {
	var (
		serverAddr = flag.String("addr", "localhost:8080", "server address")
		org        = flag.String("org", "", "GitHub organization to subscribe to")
		token      = flag.String("token", "", "GitHub personal access token")
		myEvents   = flag.Bool("my-events", false, "Only receive events for authenticated user")
		eventTypes = flag.String("events", "", "Comma-separated list of event types to subscribe to")
		useTLS     = flag.Bool("tls", false, "Use TLS (wss://)")
	)
	flag.Parse()

	if *org == "" {
		return errors.New("organization required: -org")
	}
	if *token == "" {
		return errors.New("GitHub token required: -token")
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
	config.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", *token)}

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
	sub := map[string]interface{}{
		"organization":   *org,
		"my_events_only": *myEvents,
	}

	// Add event types if specified
	if *eventTypes != "" {
		types := strings.Split(*eventTypes, ",")
		for i, t := range types {
			types[i] = strings.TrimSpace(t)
		}
		sub["event_types"] = types
	}

	if err := websocket.JSON.Send(ws, sub); err != nil {
		return fmt.Errorf("write subscription: %w", err)
	}
	log.Printf("subscribed with: %+v", sub)

	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			var event struct {
				URL       string    `json:"url"`
				Timestamp time.Time `json:"timestamp"`
				Type      string    `json:"type"`
			}
			if err := websocket.JSON.Receive(ws, &event); err != nil {
				log.Println("read:", err)
				return
			}
			fmt.Printf("[%s] %s: %s\n", event.Timestamp.Format("15:04:05"), event.Type, event.URL)
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

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
