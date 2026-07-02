package evidence

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/h3ow3d/special-dollop/internal/infra/security"
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
		logUnexpectedError(ctx, "evidence.refresh", target.InventoryItemID, fmt.Errorf("inventory item id is required"))
		return fmt.Errorf("inventory item id is required")
	}
	if target.Registry == "" || target.Repository == "" {
		logUnexpectedError(ctx, "evidence.refresh", target.InventoryItemID, fmt.Errorf("registry and repository are required for OCI discovery"))
		return fmt.Errorf("registry and repository are required for OCI discovery")
	}
	if s.discoverer == nil {
		return nil
	}

	slog.Info("inventory discovery refresh started",
		"operation", "evidence.refresh",
		"user", usernameFromContext(ctx),
		"role", roleFromContext(ctx),
		"team", teamFromContext(ctx),
		"inventory_item_id", target.InventoryItemID,
		"registry", target.Registry,
		"repository", target.Repository,
	)

	// Step 1: enumerate all tags in the repository.
	tags, err := s.discoverer.ListTags(ctx, target.Registry, target.Repository)
	if err != nil {
		logUnexpectedError(ctx, "evidence.list_tags", target.InventoryItemID, err)
		return fmt.Errorf("list tags for %s/%s: %w", target.Registry, target.Repository, err)
	}

	// Step 2: resolve each tag to a digest and upsert rows.
	// Track unique digests discovered in this scan.
	seenDigests := make(map[string]*ArtifactDigest)
	processedTags := 0
	for _, tag := range tags {
		processedTags++
		resolution, err := s.discoverer.ResolveTag(ctx, target.Registry, target.Repository, tag)
		if err != nil {
			// Non-fatal: skip this tag and continue with the next.
			slog.Warn("inventory discovery tag resolution failed",
				"operation", "evidence.resolve_tag",
				"user", usernameFromContext(ctx),
				"role", roleFromContext(ctx),
				"team", teamFromContext(ctx),
				"inventory_item_id", target.InventoryItemID,
				"tag", tag,
				"error", err.Error(),
			)
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
				logUnexpectedError(ctx, "evidence.upsert_digest", target.InventoryItemID, err)
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
			logUnexpectedError(ctx, "evidence.upsert_tag", target.InventoryItemID, err)
			return fmt.Errorf("upsert tag %q: %w", tag, err)
		}
		slog.Debug("inventory discovery progress",
			"operation", "evidence.resolve_tag",
			"user", usernameFromContext(ctx),
			"role", roleFromContext(ctx),
			"team", teamFromContext(ctx),
			"inventory_item_id", target.InventoryItemID,
			"processed_tags", processedTags,
			"total_tags", len(tags),
			"tag", tag,
			"digest", resolution.Digest,
		)
	}

	// Step 3: discover referrer evidence for every unique digest found above.
	discoveredEvidenceCount := 0
	for digest, d := range seenDigests {
		referrers, warnings, err := s.discoverer.ListReferrers(ctx, target.Registry, target.Repository, digest)
		if err != nil {
			logUnexpectedError(ctx, "evidence.list_referrers", target.InventoryItemID, err)
			if updateErr := s.repo.UpdateDigestStatus(ctx, d.ID, DiscoveryStatusFailed, err.Error(), time.Time{}); updateErr != nil {
				logUnexpectedError(ctx, "evidence.update_digest_status", target.InventoryItemID, updateErr)
				return updateErr
			}
			continue
		}

		if err := s.repo.ReplaceEvidence(ctx, d.ID, referrers); err != nil {
			logUnexpectedError(ctx, "evidence.replace", target.InventoryItemID, err)
			return fmt.Errorf("replace evidence for digest %q: %w", digest, err)
		}
		discoveredEvidenceCount += len(referrers)

		status := DiscoveryStatusSuccess
		errMsg := ""
		if len(warnings) > 0 {
			status = DiscoveryStatusWarning
			errMsg = strings.Join(warnings, "\n")
			slog.Warn("inventory discovery warnings",
				"operation", "evidence.list_referrers",
				"user", usernameFromContext(ctx),
				"role", roleFromContext(ctx),
				"team", teamFromContext(ctx),
				"inventory_item_id", target.InventoryItemID,
				"digest", digest,
				"warning_count", len(warnings),
			)
		}
		if err := s.repo.UpdateDigestStatus(ctx, d.ID, status, errMsg, now); err != nil {
			logUnexpectedError(ctx, "evidence.update_digest_status", target.InventoryItemID, err)
			return fmt.Errorf("update digest status for %q: %w", digest, err)
		}
		slog.Debug("inventory discovery progress",
			"operation", "evidence.list_referrers",
			"user", usernameFromContext(ctx),
			"role", roleFromContext(ctx),
			"team", teamFromContext(ctx),
			"inventory_item_id", target.InventoryItemID,
			"processed_digests", len(seenDigests),
			"digest", digest,
		)
	}

	slog.Info("inventory discovery refresh complete",
		"operation", "evidence.refresh",
		"user", usernameFromContext(ctx),
		"role", roleFromContext(ctx),
		"team", teamFromContext(ctx),
		"inventory_item_id", target.InventoryItemID,
		"discovered_artifact_count", len(seenDigests),
		"discovered_evidence_count", discoveredEvidenceCount,
	)

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

func logUnexpectedError(ctx context.Context, operation string, inventoryItemID int64, err error) {
	slog.Error("unexpected inventory discovery error",
		"operation", operation,
		"user", usernameFromContext(ctx),
		"role", roleFromContext(ctx),
		"team", teamFromContext(ctx),
		"inventory_item_id", inventoryItemID,
		"error", err.Error(),
	)
}

func usernameFromContext(ctx context.Context) string {
	if session, ok := security.SessionFromContext(ctx); ok {
		return session.GitHubUser.GitHubUsername
	}
	return ""
}

func roleFromContext(ctx context.Context) string {
	if session, ok := security.SessionFromContext(ctx); ok {
		return session.EffectiveRoleSlug()
	}
	return ""
}

func teamFromContext(ctx context.Context) string {
	if session, ok := security.SessionFromContext(ctx); ok {
		return session.EffectiveTeamName()
	}
	return ""
}
