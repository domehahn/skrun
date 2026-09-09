package secret

import (
	"context"
	"fmt"
	"os"
)

// Provider abstracts secret retrieval to avoid ambient environment exposure and plaintext logging.
type Provider interface {
	GetSecret(ctx context.Context, name string) (string, error)
}

type EnvSecretProvider struct{}

func (EnvSecretProvider) GetSecret(ctx context.Context, name string) (string, error) {
	if val, ok := os.LookupEnv("SKRUN_SECRET_" + name); ok {
		return val, nil
	}
	return "", fmt.Errorf("secret %q not found in environment provider", name)
}

type MapSecretProvider map[string]string

func (m MapSecretProvider) GetSecret(ctx context.Context, name string) (string, error) {
	if val, ok := m[name]; ok {
		return val, nil
	}
	return "", fmt.Errorf("secret %q not found in map provider", name)
}
