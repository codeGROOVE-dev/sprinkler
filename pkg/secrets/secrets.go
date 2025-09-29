// Package secrets provides integration with Google Secret Manager for fetching configuration.
package secrets

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/option"
)

const (
	// secretManagerTimeout prevents indefinite hangs when accessing secrets.
	secretManagerTimeout = 10 * time.Second
)

// Manager handles fetching secrets from Google Secret Manager.
type Manager struct {
	client    *secretmanager.Client
	projectID string
}

// New creates a new secrets manager with optional credentials.
// If credentialsPath is empty, it uses Application Default Credentials.
func New(ctx context.Context, projectID, credentialsPath string) (*Manager, error) {
	var opts []option.ClientOption
	if credentialsPath != "" {
		opts = append(opts, option.WithCredentialsFile(credentialsPath))
	}

	client, err := secretmanager.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %w", err)
	}

	return &Manager{
		client:    client,
		projectID: projectID,
	}, nil
}

// GetWithEnvOverride fetches a secret value from Google Secret Manager,
// but returns the environment variable value if it exists (env vars take precedence).
// The secretName should be the same as the environment variable name (e.g., "GITHUB_WEBHOOK_SECRET").
func (m *Manager) GetWithEnvOverride(ctx context.Context, envVar, secretName string) (string, error) {
	// Check environment variable first (takes precedence)
	if value := os.Getenv(envVar); value != "" {
		log.Printf("using environment variable instead of secret: env_var=%s source=environment", envVar)
		return value, nil
	}

	// Build the resource name for Secret Manager
	resourceName := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", m.projectID, secretName)

	log.Printf("attempting to access secret from Secret Manager: env_var=%s secret_name=%s project_id=%s", envVar, secretName, m.projectID)

	// Create a context with timeout to prevent indefinite hangs
	timeoutCtx, cancel := context.WithTimeout(ctx, secretManagerTimeout)
	defer cancel()

	// Access the secret version
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: resourceName,
	}

	result, err := m.client.AccessSecretVersion(timeoutCtx, req)
	if err != nil {
		log.Printf("failed to access secret from Secret Manager: env_var=%s secret_name=%s error=%v", envVar, secretName, err)
		return "", fmt.Errorf("failed to access secret %s: %w", resourceName, err)
	}

	secretValue := string(result.GetPayload().GetData())
	log.Printf("successfully fetched secret from Google Secret Manager: env_var=%s secret_name=%s has_value=%v", envVar, secretName, secretValue != "")
	return secretValue, nil
}

// Close closes the Secret Manager client connection.
func (m *Manager) Close() error {
	if m.client != nil {
		return m.client.Close()
	}
	return nil
}