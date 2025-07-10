package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"golang.org/x/net/websocket"
)

func main() {
	var (
		serverAddr = flag.String("addr", "localhost:8080", "server address")
		username   = flag.String("username", "", "GitHub username to subscribe to")
		prURL      = flag.String("pr", "", "Pull request URL to subscribe to")
		repository = flag.String("repo", "", "Repository URL to subscribe to")
		useTLS     = flag.Bool("tls", false, "Use TLS (wss://)")
	)
	flag.Parse()

	if *username == "" && *prURL == "" && *repository == "" {
		log.Fatal("At least one subscription criteria required: -username, -pr, or -repo")
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
		log.Fatal("config:", err)
	}
	
	ws, err := websocket.DialConfig(config)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer ws.Close()

	// Send subscription
	sub := map[string]string{}
	if *username != "" {
		sub["username"] = *username
	}
	if *prURL != "" {
		sub["pr_url"] = *prURL
	}
	if *repository != "" {
		sub["repository"] = *repository
	}

	if err := websocket.JSON.Send(ws, sub); err != nil {
		log.Fatal("write subscription:", err)
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
			return
		case <-interrupt:
			log.Println("interrupt")
			return
		}
	}
}
