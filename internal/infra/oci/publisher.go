package oci

import (
	"context"
	"fmt"
)

type Publisher struct{}

func NewPublisher() *Publisher { return &Publisher{} }

func (p *Publisher) Publish(_ context.Context, registry, artifactRef string, _ []byte) (string, error) {
	if registry == "" || artifactRef == "" {
		return "", fmt.Errorf("registry and artifact reference are required")
	}
	return fmt.Sprintf("%s/%s", registry, artifactRef), nil
}
