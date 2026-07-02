package evidence

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	infrolog "github.com/h3ow3d/special-dollop/internal/infra/logging"
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
	user, role, team := infrolog.UserContextFields(ctx)
	if s == nil || s.repo == nil {
		return nil
	}

	target.Registry = strings.TrimSpace(target.Registry)
	target.Repository = strings.TrimSpace(target.Repository)
	now := time.Now().UTC()

	if target.InventoryItemID <= 0 {
		logUnexpectedError("evidence.refresh", user, role, team, target.InventoryItemID, fmt.Errorf("inventory item id is required"))
		return fmt.Errorf("inventory item id is required")
	}
	if target.Registry == "" || target.Repository == "" {
		logUnexpectedError("evidence.refresh", user, role, team, target.InventoryItemID, fmt.Errorf("registry and repository are required for OCI discovery"))
		return fmt.Errorf("registry and repository are required for OCI discovery")
	}
	if s.discoverer == nil {
		return nil
	}

	slog.Info("inventory discovery refresh started",
		"operation", "evidence.refresh",
		"user", user,
		"role", role,
		"team", team,
		"inventory_item_id", target.InventoryItemID,
		"registry", target.Registry,
		"repository", target.Repository,
	)

	// Step 1: enumerate all tags in the repository.
	tags, err := s.discoverer.ListTags(ctx, target.Registry, target.Repository)
	if err != nil {
		logUnexpectedError("evidence.list_tags", user, role, team, target.InventoryItemID, err)
		return fmt.Errorf("list tags for %s/%s: %w", target.Registry, target.Repository, err)
	}

	slog.Info("inventory discovery tags enumerated",
		"operation", "evidence.list_tags",
		"user", user,
		"role", role,
		"team", team,
		"inventory_item_id", target.InventoryItemID,
		"tag_count", len(tags),
	)

	// Step 2: resolve each tag to a digest and upsert rows.
	// Tags that follow the cosign fallback referrers naming scheme
	// (sha256-<hex>.(sig|att|sbom)) are buffered as pending evidence rather than
	// stored as primary artifact rows; they will be attached to their subject
	// digest in step 3.
	seenDigests := make(map[string]*ArtifactDigest)
	// sidecarsBySubject maps a subject digest string to sidecar evidence items
	// discovered from cosign fallback tags.
	sidecarsBySubject := make(map[string][]*DigestEvidence)
	skippedTagCount := 0
	processedTags := 0
	for _, tag := range tags {
		processedTags++

		// Detect cosign fallback referrer tags and buffer as pending evidence.
		if subjectDigest, ok := parseSidecarTagSubject(tag); ok {
			resolution, err := s.discoverer.ResolveTag(ctx, target.Registry, target.Repository, tag)
			if err != nil {
				skippedTagCount++
				slog.Warn("inventory discovery sidecar tag resolution failed",
					"operation", "evidence.resolve_tag",
					"user", user,
					"role", role,
					"team", team,
					"inventory_item_id", target.InventoryItemID,
					"tag", tag,
					"error", err.Error(),
				)
				continue
			}
			sidecarsBySubject[subjectDigest] = append(sidecarsBySubject[subjectDigest], &DigestEvidence{
				Type:         classifySidecarEvidence(tag, resolution),
				Name:         tag,
				Digest:       resolution.Digest,
				MediaType:    resolution.MediaType,
				ArtifactType: resolution.ArtifactType,
			})
			slog.Debug("inventory discovery sidecar tag buffered",
				"operation", "evidence.resolve_tag",
				"user", user,
				"role", role,
				"team", team,
				"inventory_item_id", target.InventoryItemID,
				"tag", tag,
				"subject_digest", subjectDigest,
			)
			continue
		}

		resolution, err := s.discoverer.ResolveTag(ctx, target.Registry, target.Repository, tag)
		if err != nil {
			// Non-fatal: skip this tag and continue with the next.
			skippedTagCount++
			slog.Warn("inventory discovery tag resolution failed",
				"operation", "evidence.resolve_tag",
				"user", user,
				"role", role,
				"team", team,
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
				logUnexpectedError("evidence.upsert_digest", user, role, team, target.InventoryItemID, err)
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
			logUnexpectedError("evidence.upsert_tag", user, role, team, target.InventoryItemID, err)
			return fmt.Errorf("upsert tag %q: %w", tag, err)
		}
		slog.Debug("inventory discovery progress",
			"operation", "evidence.resolve_tag",
			"user", user,
			"role", role,
			"team", team,
			"inventory_item_id", target.InventoryItemID,
			"processed_tags", processedTags,
			"total_tags", len(tags),
			"tag", tag,
			"digest", resolution.Digest,
		)
	}

	// Step 3: discover referrer evidence for every unique digest found above.
	slog.Info("inventory discovery starting referrer scan",
		"operation", "evidence.list_referrers",
		"user", user,
		"role", role,
		"team", team,
		"inventory_item_id", target.InventoryItemID,
		"unique_digest_count", len(seenDigests),
		"skipped_tag_count", skippedTagCount,
	)
	discoveredEvidenceCount := 0
	processedDigests := 0
	for digest, d := range seenDigests {
		processedDigests++
		referrers, warnings, err := s.discoverer.ListReferrers(ctx, target.Registry, target.Repository, digest)
		if err != nil {
			logUnexpectedError("evidence.list_referrers", user, role, team, target.InventoryItemID, err)
			if updateErr := s.repo.UpdateDigestStatus(ctx, d.ID, DiscoveryStatusFailed, err.Error(), time.Time{}); updateErr != nil {
				logUnexpectedError("evidence.update_digest_status", user, role, team, target.InventoryItemID, updateErr)
				return updateErr
			}
			continue
		}

		// Merge evidence discovered from cosign fallback tags (e.g. GHCR, which
		// does not fully support the OCI referrers API). These are deduped by
		// the ON CONFLICT clause in ReplaceEvidence.
		if sidecars, ok := sidecarsBySubject[digest]; ok {
			referrers = append(referrers, sidecars...)
		}

		if err := s.repo.ReplaceEvidence(ctx, d.ID, referrers); err != nil {
			logUnexpectedError("evidence.replace", user, role, team, target.InventoryItemID, err)
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
				"user", user,
				"role", role,
				"team", team,
				"inventory_item_id", target.InventoryItemID,
				"digest", digest,
				"warning_count", len(warnings),
			)
		}
		if err := s.repo.UpdateDigestStatus(ctx, d.ID, status, errMsg, now); err != nil {
			logUnexpectedError("evidence.update_digest_status", user, role, team, target.InventoryItemID, err)
			return fmt.Errorf("update digest status for %q: %w", digest, err)
		}
		slog.Debug("inventory discovery progress",
			"operation", "evidence.list_referrers",
			"user", user,
			"role", role,
			"team", team,
			"inventory_item_id", target.InventoryItemID,
			"processed_digests", processedDigests,
			"total_digests", len(seenDigests),
			"digest", digest,
		)
	}

	slog.Info("inventory discovery refresh complete",
		"operation", "evidence.refresh",
		"user", user,
		"role", role,
		"team", team,
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

func logUnexpectedError(operation, user, role, team string, inventoryItemID int64, err error) {
	slog.Error("unexpected inventory discovery error",
		"operation", operation,
		"user", user,
		"role", role,
		"team", team,
		"inventory_item_id", inventoryItemID,
		"error", err.Error(),
	)
}

// sidecarTagRE matches cosign fallback referrers tags of the form
// sha256-<64 hex chars>.(sig|att|sbom). These encode the subject digest in the
// tag name and must not be treated as primary container image artifacts.
var sidecarTagRE = regexp.MustCompile(`^sha256-([a-f0-9]{64})\.(sig|att|sbom)$`)

// parseSidecarTagSubject returns the OCI subject digest encoded in a cosign
// fallback referrers tag (e.g. "sha256-abc…123.sig" → "sha256:abc…123").
// Returns ok=false when tag does not follow that naming scheme.
func parseSidecarTagSubject(tag string) (subjectDigest string, ok bool) {
	m := sidecarTagRE.FindStringSubmatch(tag)
	if m == nil {
		return "", false
	}
	return "sha256:" + m[1], true
}

// classifySidecarEvidence classifies a resolved sidecar tag into an EvidenceType.
// The tag suffix is the primary signal; ArtifactType is used as a tiebreaker
// for .att tags which may carry either attestations or provenance.
func classifySidecarEvidence(tag string, r *TagResolution) EvidenceType {
	switch {
	case strings.HasSuffix(tag, ".sig"):
		return EvidenceTypeSignature
	case strings.HasSuffix(tag, ".sbom"):
		return EvidenceTypeSBOM
	case strings.HasSuffix(tag, ".att"):
		at := strings.ToLower(r.ArtifactType)
		if strings.Contains(at, "provenance") || strings.Contains(at, "slsa") {
			return EvidenceTypeProvenance
		}
		return EvidenceTypeAttestation
	}
	// Fallback for non-cosign sidecar formats: classify by manifest fields.
	s := strings.ToLower(r.MediaType + " " + r.ArtifactType)
	switch {
	case strings.Contains(s, "signature"), strings.Contains(s, "simplesigning"):
		return EvidenceTypeSignature
	case strings.Contains(s, "sbom"), strings.Contains(s, "spdx"), strings.Contains(s, "cyclonedx"):
		return EvidenceTypeSBOM
	case strings.Contains(s, "provenance"), strings.Contains(s, "slsa"):
		return EvidenceTypeProvenance
	default:
		return EvidenceTypeAttestation
	}
}
