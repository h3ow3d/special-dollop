package evidence

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// RepositoryDiscoverer resolves OCI metadata and evidence for all tags in a
// repository. The OCI discoverer in infra/oci implements this interface.
type RepositoryDiscoverer interface {
	ListTags(ctx context.Context, registry, repository string) ([]string, error)
	ResolveTag(ctx context.Context, registry, repository, tag string) (*TagResolution, error)
	ListReferrers(ctx context.Context, registry, repository, digest string) ([]*DigestEvidence, []string, error)
}

// Service orchestrates repository-scoped evidence discovery and persistence.
type Service struct {
	repo       Repository
	discoverer RepositoryDiscoverer
}

// NewService creates an evidence service.
func NewService(repo Repository, discoverer RepositoryDiscoverer) *Service {
	return &Service{repo: repo, discoverer: discoverer}
}

// RefreshRepository discovers all tags in the repository, resolves each tag to
// an immutable digest, and discovers referrer evidence for every unique digest.
// Errors during individual tag or evidence resolution are tolerated; they are
// stored as per-digest discovery status and do not abort the full scan.
func (s *Service) RefreshRepository(ctx context.Context, target DiscoveryTarget) error {
	if s == nil || s.repo == nil {
		return nil
	}

	target.Registry = strings.TrimSpace(target.Registry)
	target.Repository = strings.TrimSpace(target.Repository)
	now := time.Now().UTC()

	if target.InventoryItemID <= 0 {
		return fmt.Errorf("inventory item id is required")
	}
	if target.Registry == "" || target.Repository == "" {
		return fmt.Errorf("registry and repository are required for OCI discovery")
	}
	if s.discoverer == nil {
		return nil
	}

	// Step 1: enumerate all tags in the repository.
	tags, err := s.discoverer.ListTags(ctx, target.Registry, target.Repository)
	if err != nil {
		return fmt.Errorf("list tags for %s/%s: %w", target.Registry, target.Repository, err)
	}

	// Step 2: resolve each tag to a digest and upsert rows.
	// Track unique digests discovered in this scan.
	seenDigests := make(map[string]*ArtifactDigest)
	for _, tag := range tags {
		resolution, err := s.discoverer.ResolveTag(ctx, target.Registry, target.Repository, tag)
		if err != nil {
			// Non-fatal: skip this tag and continue with the next.
			continue
		}

		d, ok := seenDigests[resolution.Digest]
		if !ok {
			d = &ArtifactDigest{
				InventoryItemID: target.InventoryItemID,
				Digest:          resolution.Digest,
				MediaType:       resolution.MediaType,
				ArtifactType:    resolution.ArtifactType,
				SizeBytes:       resolution.SizeBytes,
				DiscoveryStatus: DiscoveryStatusPending,
				LastRefreshAt:   now,
			}
			if err := s.repo.UpsertDigest(ctx, d); err != nil {
				return fmt.Errorf("upsert digest %q: %w", resolution.Digest, err)
			}
			seenDigests[resolution.Digest] = d
		}

		digestID := d.ID
		rt := &RepositoryTag{
			InventoryItemID:  target.InventoryItemID,
			Tag:              tag,
			ArtifactDigestID: &digestID,
			LastSeenAt:       now,
		}
		if err := s.repo.UpsertTag(ctx, rt); err != nil {
			return fmt.Errorf("upsert tag %q: %w", tag, err)
		}
	}

	// Step 3: discover referrer evidence for every unique digest found above.
	for digest, d := range seenDigests {
		referrers, warnings, err := s.discoverer.ListReferrers(ctx, target.Registry, target.Repository, digest)
		if err != nil {
			if updateErr := s.repo.UpdateDigestStatus(ctx, d.ID, DiscoveryStatusFailed, err.Error(), time.Time{}); updateErr != nil {
				return updateErr
			}
			continue
		}

		if err := s.repo.ReplaceEvidence(ctx, d.ID, referrers); err != nil {
			return fmt.Errorf("replace evidence for digest %q: %w", digest, err)
		}

		status := DiscoveryStatusSuccess
		errMsg := ""
		if len(warnings) > 0 {
			status = DiscoveryStatusWarning
			errMsg = strings.Join(warnings, "\n")
		}
		if err := s.repo.UpdateDigestStatus(ctx, d.ID, status, errMsg, now); err != nil {
			return fmt.Errorf("update digest status for %q: %w", digest, err)
		}
	}

	return nil
}

// GetDigestByID returns a single artifact digest with its evidence and tag names.
func (s *Service) GetDigestByID(ctx context.Context, id int64) (*ArtifactDigest, error) {
	if s == nil || s.repo == nil {
		return nil, nil
	}
	return s.repo.GetDigestByID(ctx, id)
}

// ListDigestsByItem returns all discovered digests for an inventory item,
// including their associated evidence and tag names.
func (s *Service) ListDigestsByItem(ctx context.Context, inventoryItemID int64) ([]*ArtifactDigest, error) {
	if s == nil || s.repo == nil {
		return nil, nil
	}
	return s.repo.ListDigestsByItem(ctx, inventoryItemID)
}

// ListTagsByItem returns all discovered repository tags for an inventory item.
func (s *Service) ListTagsByItem(ctx context.Context, inventoryItemID int64) ([]*RepositoryTag, error) {
	if s == nil || s.repo == nil {
		return nil, nil
	}
	return s.repo.ListTagsByItem(ctx, inventoryItemID)
}

// GetSummaries returns a per-inventory-item discovery summary map, used for
// efficient display in the inventory list view.
func (s *Service) GetSummaries(ctx context.Context) (map[int64]*RepositorySummary, error) {
	if s == nil || s.repo == nil {
		return nil, nil
	}
	return s.repo.GetSummaries(ctx)
}
