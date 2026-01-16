package srv

import (
	"context"

	"golang.org/x/net/websocket"

	"github.com/codeGROOVE-dev/sprinkler/pkg/github"
)

// NewClientForTest creates a new client for testing with default TierFree.
// This maintains backward compatibility with existing tests.
func NewClientForTest(ctx context.Context, id string, sub Subscription, conn *websocket.Conn, hub *Hub, userOrgs []string) *Client {
	return NewClient(ctx, id, sub, conn, hub, userOrgs, github.TierFree)
}
