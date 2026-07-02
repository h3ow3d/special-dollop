// Package oci provides OCI artefact integration for attaching attestations.
//
// The Publisher interface is designed to support Cosign and ORAS as backing
// implementations. The stub implementation logs the intended action and returns
// a synthetic reference; it is suitable for development and local registry use.
//
// Future implementations should support:
//   - cosign attest (Sigstore keyless or local key)
//   - oras attach (ORAS v2 referrers API)
//   - Internal Fulcio / Rekor when available
package oci

import (
"context"
"fmt"
"log"
)

// Publisher attaches a signed attestation envelope to an OCI artefact.
// Implementations must be safe for concurrent use.
type Publisher interface {
Publish(ctx context.Context, registry, ref string, envelope []byte) (ociRef string, err error)
}

// StubPublisher is a development-mode publisher that logs the intended action
// without making network calls. It is used when no real OCI registry is configured.
type StubPublisher struct{}

// NewStubPublisher returns a StubPublisher.
func NewStubPublisher() *StubPublisher { return &StubPublisher{} }

// Publish logs the publish intent and returns a synthetic OCI reference.
// In production, replace this with a Cosign or ORAS implementation.
func (p *StubPublisher) Publish(_ context.Context, registry, ref string, envelope []byte) (string, error) {
if registry == "" || ref == "" {
return "", fmt.Errorf("registry and artefact reference are required")
}
log.Printf("[oci/stub] would attach %d-byte attestation envelope to %s/%s", len(envelope), registry, ref)
return fmt.Sprintf("%s/%s", registry, ref), nil
}
