package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/h3ow3d/special-dollop/internal/evidence"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// Discoverer resolves artifact metadata and evidence from a registry.
type Discoverer struct {
	username  string
	password  string
	plainHTTP bool
}

// NewDiscoverer returns an ORAS-backed OCI metadata discoverer.
func NewDiscoverer(cfg PublisherConfig) *Discoverer {
	return &Discoverer{
		username:  strings.TrimSpace(cfg.Username),
		password:  strings.TrimSpace(cfg.Password),
		plainHTTP: cfg.PlainHTTP,
	}
}

// Discover resolves the supplied target and enumerates known evidence
// referrers. The initial implementation is GHCR-oriented by design.
func (d *Discoverer) Discover(ctx context.Context, target evidence.DiscoveryTarget) (*evidence.DiscoveryResult, error) {
	if target.Registry != "ghcr.io" {
		return nil, fmt.Errorf("registry %q is not supported for OCI discovery yet", target.Registry)
	}

	reference, err := inventoryReference(target.Registry, target.Repository, target.Reference)
	if err != nil {
		return nil, err
	}
	parsed, err := normalizeReference(target.Registry, reference)
	if err != nil {
		return nil, err
	}

	repo, err := remote.NewRepository(parsed.Registry + "/" + parsed.Repository)
	if err != nil {
		return nil, fmt.Errorf("create repository client: %w", err)
	}
	repo.PlainHTTP = d.plainHTTP
	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: func(_ context.Context, hostport string) (auth.Credential, error) {
			if hostport != parsed.Registry || d.username == "" || d.password == "" {
				return auth.EmptyCredential, nil
			}
			return auth.Credential{Username: d.username, Password: d.password}, nil
		},
	}

	desc, err := repo.Resolve(ctx, parsed.Reference)
	if err != nil {
		return nil, fmt.Errorf("resolve artefact reference %q: %w", parsed.Reference, err)
	}

	fetchedDesc, rc, err := repo.FetchReference(ctx, parsed.Reference)
	if err != nil {
		return nil, fmt.Errorf("fetch artefact manifest: %w", err)
	}
	defer rc.Close()

	manifestBytes, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("read artefact manifest: %w", err)
	}

	result := &evidence.DiscoveryResult{
		Registry:          target.Registry,
		Repository:        target.Repository,
		Reference:         target.Reference,
		ResolvedReference: fmt.Sprintf("%s/%s@%s", parsed.Registry, parsed.Repository, desc.Digest.String()),
		Digest:            desc.Digest.String(),
		MediaType:         firstNonEmpty(desc.MediaType, fetchedDesc.MediaType),
		SizeBytes:         desc.Size,
	}
	populateManifestMetadata(result, manifestBytes)

	if err := repo.Referrers(ctx, desc, "", func(referrers []ocispec.Descriptor) error {
		for _, referrer := range referrers {
			result.Evidence = append(result.Evidence, descriptorToEvidence(referrer))
		}
		return nil
	}); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("failed to enumerate OCI referrers: %v", err))
	}

	return result, nil
}

func inventoryReference(registryHost, repository, reference string) (string, error) {
	registryHost = strings.TrimSpace(strings.TrimSuffix(registryHost, "/"))
	repository = strings.Trim(strings.TrimSpace(repository), "/")
	reference = strings.TrimSpace(reference)
	if registryHost == "" || repository == "" || reference == "" {
		return "", fmt.Errorf("registry, repository, and reference are required")
	}

	base := registryHost + "/" + repository
	switch {
	case hasExplicitRegistry(reference):
		return reference, nil
	case strings.HasPrefix(reference, "@"):
		return base + reference, nil
	case strings.HasPrefix(reference, "sha256:"):
		return base + "@" + reference, nil
	default:
		return base + ":" + strings.TrimPrefix(reference, ":"), nil
	}
}

func populateManifestMetadata(result *evidence.DiscoveryResult, manifestBytes []byte) {
	switch result.MediaType {
	case ocispec.MediaTypeImageManifest:
		var manifest ocispec.Manifest
		if err := json.Unmarshal(manifestBytes, &manifest); err == nil {
			result.MediaType = firstNonEmpty(result.MediaType, manifest.MediaType)
			result.ArtifactType = manifest.ArtifactType
		}
	case ocispec.MediaTypeImageIndex:
		var index ocispec.Index
		if err := json.Unmarshal(manifestBytes, &index); err == nil {
			result.MediaType = firstNonEmpty(result.MediaType, index.MediaType)
			result.ArtifactType = index.ArtifactType
		}
	}
}

func descriptorToEvidence(desc ocispec.Descriptor) *evidence.ArtifactEvidence {
	return &evidence.ArtifactEvidence{
		Type:         classifyEvidence(desc),
		Name:         firstNonEmpty(desc.Annotations["org.opencontainers.image.title"], desc.ArtifactType, desc.Digest.String()),
		Digest:       desc.Digest.String(),
		MediaType:    desc.MediaType,
		ArtifactType: desc.ArtifactType,
		Annotations:  copyAnnotations(desc.Annotations),
	}
}

func classifyEvidence(desc ocispec.Descriptor) evidence.EvidenceType {
	s := strings.ToLower(strings.Join([]string{
		desc.MediaType,
		desc.ArtifactType,
		desc.Annotations["org.opencontainers.image.title"],
		desc.Annotations["dev.clph.predicateType"],
	}, " "))

	switch {
	case strings.Contains(s, "signature"), strings.Contains(s, "simplesigning"), strings.Contains(s, "cosign"):
		return evidence.EvidenceTypeSignature
	case strings.Contains(s, "sbom"), strings.Contains(s, "spdx"), strings.Contains(s, "cyclonedx"):
		return evidence.EvidenceTypeSBOM
	case strings.Contains(s, "provenance"), strings.Contains(s, "slsa"):
		return evidence.EvidenceTypeProvenance
	default:
		return evidence.EvidenceTypeAttestation
	}
}

func copyAnnotations(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
