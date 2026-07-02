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
// It implements evidence.RepositoryDiscoverer.
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

// newRepository builds an authenticated ORAS remote.Repository for the given
// registry and repository path.
func (d *Discoverer) newRepository(registry, repository string) (*remote.Repository, error) {
	registry = strings.TrimSpace(strings.TrimSuffix(registry, "/"))
	repository = strings.Trim(strings.TrimSpace(repository), "/")

	repo, err := remote.NewRepository(registry + "/" + repository)
	if err != nil {
		return nil, fmt.Errorf("create repository client: %w", err)
	}
	repo.PlainHTTP = d.plainHTTP
	repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: func(_ context.Context, hostport string) (auth.Credential, error) {
			if hostport != registry || d.username == "" || d.password == "" {
				return auth.EmptyCredential, nil
			}
			return auth.Credential{Username: d.username, Password: d.password}, nil
		},
	}
	return repo, nil
}

// ListTags returns all tags available in the repository.
func (d *Discoverer) ListTags(ctx context.Context, registry, repository string) ([]string, error) {
	repo, err := d.newRepository(registry, repository)
	if err != nil {
		return nil, err
	}

	var tags []string
	if err := repo.Tags(ctx, "", func(batch []string) error {
		tags = append(tags, batch...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("list tags for %s/%s: %w", registry, repository, err)
	}
	return tags, nil
}

// ResolveTag resolves a single tag to its immutable digest and fetches
// manifest metadata (media type, artifact type, size).
func (d *Discoverer) ResolveTag(ctx context.Context, registry, repository, tag string) (*evidence.TagResolution, error) {
	repo, err := d.newRepository(registry, repository)
	if err != nil {
		return nil, err
	}

	ref := registry + "/" + repository + ":" + tag
	desc, err := repo.Resolve(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("resolve tag %q: %w", ref, err)
	}

	// Fetch the manifest to get artifact type (not present in the descriptor alone).
	_, rc, err := repo.FetchReference(ctx, tag)
	if err != nil {
		// Non-fatal: we have the digest; use what we have.
		return &evidence.TagResolution{
			Tag:          tag,
			Digest:       desc.Digest.String(),
			MediaType:    desc.MediaType,
			ArtifactType: desc.ArtifactType,
			SizeBytes:    desc.Size,
		}, nil
	}
	defer rc.Close()

	manifestBytes, err := io.ReadAll(rc)
	if err != nil {
		return &evidence.TagResolution{
			Tag:          tag,
			Digest:       desc.Digest.String(),
			MediaType:    desc.MediaType,
			ArtifactType: desc.ArtifactType,
			SizeBytes:    desc.Size,
		}, nil
	}

	resolution := &evidence.TagResolution{
		Tag:       tag,
		Digest:    desc.Digest.String(),
		MediaType: firstNonEmpty(desc.MediaType),
		SizeBytes: desc.Size,
	}
	enrichResolutionFromManifest(resolution, manifestBytes)
	return resolution, nil
}

// ListReferrers discovers all OCI referrer objects (signatures, SBOMs,
// attestations, provenance) for a specific digest. Non-critical per-referrer
// issues are returned as warnings rather than errors.
func (d *Discoverer) ListReferrers(ctx context.Context, registry, repository, digest string) ([]*evidence.DigestEvidence, []string, error) {
	repo, err := d.newRepository(registry, repository)
	if err != nil {
		return nil, nil, err
	}

	ref := registry + "/" + repository + "@" + digest
	desc, err := repo.Resolve(ctx, digest)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve digest %q: %w", ref, err)
	}

	var referrers []*evidence.DigestEvidence
	var warnings []string

	if err := repo.Referrers(ctx, desc, "", func(batch []ocispec.Descriptor) error {
		for _, r := range batch {
			referrers = append(referrers, descriptorToEvidence(r))
		}
		return nil
	}); err != nil {
		warnings = append(warnings, fmt.Sprintf("failed to enumerate OCI referrers: %v", err))
	}

	return referrers, warnings, nil
}

func enrichResolutionFromManifest(resolution *evidence.TagResolution, manifestBytes []byte) {
	switch resolution.MediaType {
	case ocispec.MediaTypeImageManifest:
		var manifest ocispec.Manifest
		if err := json.Unmarshal(manifestBytes, &manifest); err == nil {
			resolution.MediaType = firstNonEmpty(resolution.MediaType, manifest.MediaType)
			resolution.ArtifactType = manifest.ArtifactType
		}
	case ocispec.MediaTypeImageIndex:
		var index ocispec.Index
		if err := json.Unmarshal(manifestBytes, &index); err == nil {
			resolution.MediaType = firstNonEmpty(resolution.MediaType, index.MediaType)
			resolution.ArtifactType = index.ArtifactType
		}
	}
}

func descriptorToEvidence(desc ocispec.Descriptor) *evidence.DigestEvidence {
	return &evidence.DigestEvidence{
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

