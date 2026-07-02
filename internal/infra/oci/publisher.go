// Package oci provides OCI artefact integration for attaching attestations.
package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

const (
	dsseEnvelopeMediaType = "application/vnd.dsse.envelope.v1+json"
	inTotoPayloadType     = "application/vnd.in-toto+json"
	clphPredicateType     = "https://clph.internal/suitability/v1"
)

// Publisher attaches a signed attestation envelope to an OCI artefact.
// Implementations must be safe for concurrent use.
type Publisher struct {
	username  string
	password  string
	plainHTTP bool
}

// PublisherConfig configures the registry client used for attestation publication.
type PublisherConfig struct {
	Username  string
	Password  string
	PlainHTTP bool
}

// NewPublisher returns a Publisher that uploads DSSE envelopes as OCI referrers.
func NewPublisher(cfg PublisherConfig) *Publisher {
	return &Publisher{
		username:  strings.TrimSpace(cfg.Username),
		password:  strings.TrimSpace(cfg.Password),
		plainHTTP: cfg.PlainHTTP,
	}
}

// Publish attaches the DSSE envelope to the referenced OCI artefact and returns
// the published attestation manifest digest reference.
func (p *Publisher) Publish(ctx context.Context, registryHost, ref string, envelope []byte) (string, error) {
	if len(envelope) == 0 {
		return "", errors.New("attestation envelope is required")
	}
	if err := p.validateCredentials(); err != nil {
		return "", err
	}

	targetRef, err := normalizeReference(registryHost, ref)
	if err != nil {
		return "", err
	}

	repo, err := remote.NewRepository(targetRef.Registry + "/" + targetRef.Repository)
	if err != nil {
		return "", fmt.Errorf("create repository client: %w", err)
	}
	repo.PlainHTTP = p.plainHTTP
	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		// The publisher resolves and pushes within a single target repository, so
		// only the resolved target registry should ever need credentials here.
		Credential: func(_ context.Context, hostport string) (auth.Credential, error) {
			if p.username == "" || p.password == "" || hostport != targetRef.Registry {
				return auth.EmptyCredential, nil
			}
			return auth.Credential{
				Username: p.username,
				Password: p.password,
			}, nil
		},
	}

	subjectDesc, err := repo.Resolve(ctx, targetRef.Reference)
	if err != nil {
		return "", fmt.Errorf("resolve subject %q: %w", targetRef.Reference, err)
	}

	layerDesc, err := oras.PushBytes(ctx, repo, dsseEnvelopeMediaType, envelope)
	if err != nil {
		return "", fmt.Errorf("push attestation blob: %w", err)
	}
	layerDesc.Annotations = map[string]string{
		"org.opencontainers.image.title": "clph-attestation.dsse.json",
	}
	if predicateType := predicateTypeFromEnvelope(envelope); predicateType != "" {
		layerDesc.Annotations["dev.clph.predicateType"] = predicateType
	}

	manifestDesc, err := oras.PackManifest(
		ctx,
		repo,
		oras.PackManifestVersion1_1,
		dsseEnvelopeMediaType,
		oras.PackManifestOptions{
			Subject:             &subjectDesc,
			Layers:              []ocispec.Descriptor{layerDesc},
			ManifestAnnotations: manifestAnnotations(envelope),
		},
	)
	if err != nil {
		return "", fmt.Errorf("push attestation manifest: %w", err)
	}

	return fmt.Sprintf("%s/%s@%s", targetRef.Registry, targetRef.Repository, manifestDesc.Digest.String()), nil
}

func (p *Publisher) validateCredentials() error {
	if (p.username == "" && p.password != "") || (p.username != "" && p.password == "") {
		return errors.New("oci credentials must include both OCI_USERNAME and OCI_PASSWORD")
	}
	return nil
}

func normalizeReference(registryHost, ref string) (registry.Reference, error) {
	registryHost = strings.TrimSpace(strings.TrimSuffix(registryHost, "/"))
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return registry.Reference{}, errors.New("artefact reference is required")
	}

	parseInput := ref
	if registryHost != "" && !hasExplicitRegistry(ref) {
		parseInput = registryHost + "/" + strings.TrimPrefix(ref, "/")
	}

	parsed, err := registry.ParseReference(parseInput)
	if err != nil {
		return registry.Reference{}, fmt.Errorf("parse artefact reference: %w", err)
	}

	if registryHost != "" && parsed.Registry != registryHost {
		return registry.Reference{}, fmt.Errorf("artefact reference registry %q does not match registry host %q", parsed.Registry, registryHost)
	}
	if parsed.Reference == "" {
		return registry.Reference{}, errors.New("artefact reference must include a tag or digest")
	}
	return parsed, nil
}

func hasExplicitRegistry(ref string) bool {
	first, _, found := strings.Cut(ref, "/")
	if !found {
		return false
	}
	return first == "localhost" || strings.Contains(first, ".") || strings.Contains(first, ":")
}

func manifestAnnotations(envelope []byte) map[string]string {
	annotations := map[string]string{
		"org.opencontainers.image.title": "clph-attestation-manifest",
		"dev.clph.content":               "dsse-envelope",
	}
	if predicateType := predicateTypeFromEnvelope(envelope); predicateType != "" {
		annotations["dev.clph.predicateType"] = predicateType
	}
	return annotations
}

func predicateTypeFromEnvelope(envelope []byte) string {
	var env struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		return ""
	}
	if env.PayloadType != inTotoPayloadType || env.Payload == "" {
		return ""
	}

	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return ""
	}

	var statement struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(payload, &statement); err != nil {
		return ""
	}
	return statement.PredicateType
}
