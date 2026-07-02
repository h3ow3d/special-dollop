package evidence

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Discoverer resolves OCI metadata and evidence for an inventory item.
type Discoverer interface {
	Discover(ctx context.Context, target DiscoveryTarget) (*DiscoveryResult, error)
}

// Service orchestrates evidence discovery and persistence.
type Service struct {
	repo       Repository
	discoverer Discoverer
}

// NewService creates an evidence service.
func NewService(repo Repository, discoverer Discoverer) *Service {
	return &Service{repo: repo, discoverer: discoverer}
}

// Refresh discovers and persists the latest artifact metadata and evidence for
// the specified inventory item. Discovery failures are recorded as metadata so
// callers can still render status on the inventory page.
func (s *Service) Refresh(ctx context.Context, target DiscoveryTarget) error {
	if s == nil || s.repo == nil {
		return nil
	}

	target.Registry = strings.TrimSpace(target.Registry)
	target.Repository = strings.TrimSpace(target.Repository)
	target.Reference = strings.TrimSpace(target.Reference)
	now := time.Now().UTC()

	base := &ArtifactMetadata{
		InventoryItemID: target.InventoryItemID,
		Registry:        target.Registry,
		Repository:      target.Repository,
		Reference:       target.Reference,
		LastRefreshAt:   now,
	}

	if target.InventoryItemID <= 0 {
		return fmt.Errorf("inventory item id is required")
	}
	if target.Registry == "" || target.Repository == "" || target.Reference == "" {
		base.DiscoveryStatus = DiscoveryStatusFailed
		base.DiscoveryError = "registry, repository, and reference are required for OCI discovery"
		return s.repo.Save(ctx, base, nil)
	}
	if s.discoverer == nil {
		base.DiscoveryStatus = DiscoveryStatusFailed
		base.DiscoveryError = "oci discovery is not configured"
		return s.repo.Save(ctx, base, nil)
	}

	result, err := s.discoverer.Discover(ctx, target)
	if err != nil {
		base.DiscoveryStatus = DiscoveryStatusFailed
		base.DiscoveryError = err.Error()
		return s.repo.Save(ctx, base, nil)
	}

	base.ResolvedReference = result.ResolvedReference
	base.Digest = result.Digest
	base.MediaType = result.MediaType
	base.ArtifactType = result.ArtifactType
	base.SizeBytes = result.SizeBytes
	base.LastDiscoveredAt = now
	if len(result.Warnings) > 0 {
		base.DiscoveryStatus = DiscoveryStatusWarning
		base.DiscoveryError = strings.Join(result.Warnings, "\n")
	} else {
		base.DiscoveryStatus = DiscoveryStatusSuccess
	}

	return s.repo.Save(ctx, base, result.Evidence)
}

// GetByInventoryItemID returns the latest persisted metadata and evidence.
func (s *Service) GetByInventoryItemID(ctx context.Context, inventoryItemID int64) (*ArtifactMetadata, error) {
	if s == nil || s.repo == nil {
		return nil, nil
	}
	return s.repo.GetByInventoryItemID(ctx, inventoryItemID)
}
