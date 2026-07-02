package evidence

import (
	"context"
	"errors"
	"testing"
)

type memRepository struct {
	metadata map[int64]*ArtifactMetadata
}

func newMemEvidenceRepo() *memRepository {
	return &memRepository{metadata: make(map[int64]*ArtifactMetadata)}
}

func (r *memRepository) Save(_ context.Context, metadata *ArtifactMetadata, evidence []*ArtifactEvidence) error {
	cp := *metadata
	cp.Evidence = append([]*ArtifactEvidence(nil), evidence...)
	r.metadata[metadata.InventoryItemID] = &cp
	return nil
}

func (r *memRepository) GetByInventoryItemID(_ context.Context, inventoryItemID int64) (*ArtifactMetadata, error) {
	if metadata, ok := r.metadata[inventoryItemID]; ok {
		cp := *metadata
		cp.Evidence = append([]*ArtifactEvidence(nil), metadata.Evidence...)
		return &cp, nil
	}
	return nil, nil
}

type fakeDiscoverer struct {
	result *DiscoveryResult
	err    error
}

func (d *fakeDiscoverer) Discover(_ context.Context, _ DiscoveryTarget) (*DiscoveryResult, error) {
	if d.err != nil {
		return nil, d.err
	}
	return d.result, nil
}

func TestServiceRefreshSuccess(t *testing.T) {
	repo := newMemEvidenceRepo()
	svc := NewService(repo, &fakeDiscoverer{
		result: &DiscoveryResult{
			ResolvedReference: "ghcr.io/org/repo@sha256:abc",
			Digest:            "sha256:abc",
			MediaType:         "application/vnd.oci.image.manifest.v1+json",
			Evidence: []*ArtifactEvidence{{
				Type:   EvidenceTypeSignature,
				Name:   "sig",
				Digest: "sha256:def",
			}},
		},
	})

	if err := svc.Refresh(context.Background(), DiscoveryTarget{
		InventoryItemID: 1,
		Registry:        "ghcr.io",
		Repository:      "org/repo",
		Reference:       "latest",
	}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	metadata, err := svc.GetByInventoryItemID(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetByInventoryItemID: %v", err)
	}
	if metadata == nil {
		t.Fatal("expected metadata to be saved")
	}
	if metadata.DiscoveryStatus != DiscoveryStatusSuccess {
		t.Fatalf("expected success status, got %q", metadata.DiscoveryStatus)
	}
	if metadata.Digest != "sha256:abc" {
		t.Fatalf("expected digest to be saved, got %q", metadata.Digest)
	}
	if len(metadata.Evidence) != 1 {
		t.Fatalf("expected 1 evidence item, got %d", len(metadata.Evidence))
	}
}

func TestServiceRefreshFailurePersistsStatus(t *testing.T) {
	repo := newMemEvidenceRepo()
	svc := NewService(repo, &fakeDiscoverer{err: errors.New("boom")})

	if err := svc.Refresh(context.Background(), DiscoveryTarget{
		InventoryItemID: 2,
		Registry:        "ghcr.io",
		Repository:      "org/repo",
		Reference:       "latest",
	}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	metadata, err := svc.GetByInventoryItemID(context.Background(), 2)
	if err != nil {
		t.Fatalf("GetByInventoryItemID: %v", err)
	}
	if metadata == nil {
		t.Fatal("expected metadata to be saved")
	}
	if metadata.DiscoveryStatus != DiscoveryStatusFailed {
		t.Fatalf("expected failed status, got %q", metadata.DiscoveryStatus)
	}
	if metadata.DiscoveryError != "boom" {
		t.Fatalf("expected discovery error to be persisted, got %q", metadata.DiscoveryError)
	}
}
