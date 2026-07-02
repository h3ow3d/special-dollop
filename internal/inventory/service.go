package inventory

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/h3ow3d/special-dollop/internal/evidence"
	infrolog "github.com/h3ow3d/special-dollop/internal/infra/logging"
)

// Service provides inventory management operations.
type Service struct {
	repo        Repository
	evidenceSvc *evidence.Service
}

// NewService creates a Service backed by the provided Repository.
func NewService(repo Repository, evidenceSvc *evidence.Service) *Service {
	return &Service{repo: repo, evidenceSvc: evidenceSvc}
}

// Create persists a new inventory item. The item's TeamID must be set by the
// caller; the service does not enforce team ownership rules.
func (s *Service) Create(ctx context.Context, item *InventoryItem) error {
	user, role, team := infrolog.UserContextFields(ctx)
	item.Active = true
	if err := s.repo.Create(ctx, item); err != nil {
		logError("inventory.create", user, role, team, item.ID, err)
		return fmt.Errorf("create inventory item: %w", err)
	}
	slog.Info("inventory item created",
		"operation", "inventory.create",
		"user", user,
		"role", role,
		"team", team,
		"inventory_item_id", item.ID,
		"inventory_name", item.Name,
		"inventory_team_id", item.TeamID,
	)
	return nil
}

// GetByID retrieves an inventory item by its ID.
func (s *Service) GetByID(ctx context.Context, id int64) (*InventoryItem, error) {
	return s.repo.GetByID(ctx, id)
}

// Update persists changes to an existing inventory item. Only the mutable
// fields (Name, Description, Registry, PackageURL, PackageName, RepositoryURL)
// are updated; Active and TeamID are not changed by this method.
func (s *Service) Update(ctx context.Context, item *InventoryItem) error {
	user, role, team := infrolog.UserContextFields(ctx)
	if err := s.repo.Update(ctx, item); err != nil {
		logError("inventory.update", user, role, team, item.ID, err)
		return fmt.Errorf("update inventory item: %w", err)
	}
	slog.Info("inventory item updated",
		"operation", "inventory.update",
		"user", user,
		"role", role,
		"team", team,
		"inventory_item_id", item.ID,
		"inventory_name", item.Name,
	)
	return nil
}

// SetActive activates or deactivates an inventory item.
func (s *Service) SetActive(ctx context.Context, id int64, active bool) error {
	return s.repo.SetActive(ctx, id, active)
}

// List returns all inventory items joined with their owning team names.
func (s *Service) List(ctx context.Context) ([]*InventoryItemWithTeam, error) {
	return s.repo.List(ctx)
}

// ListByTeam returns all inventory items belonging to a specific team.
func (s *Service) ListByTeam(ctx context.Context, teamID int64) ([]*InventoryItemWithTeam, error) {
	return s.repo.ListByTeam(ctx, teamID)
}

// CountByTeam returns the count of active inventory items per team ID.
func (s *Service) CountByTeam(ctx context.Context) (map[int64]int, error) {
	return s.repo.CountByTeam(ctx)
}

// RefreshEvidence re-runs OCI discovery for the specified inventory item and
// propagates errors so the HTTP handler can surface them to the user.
func (s *Service) RefreshEvidence(ctx context.Context, id int64) error {
	user, role, team := infrolog.UserContextFields(ctx)
	item, err := s.repo.GetByID(ctx, id)
	if err != nil {
		logError("inventory.refresh", user, role, team, id, err)
		return err
	}
	slog.Info("inventory refresh requested",
		"operation", "inventory.refresh",
		"user", user,
		"role", role,
		"team", team,
		"inventory_item_id", id,
	)
	return s.refreshEvidence(ctx, item)
}

// GetArtifactDigests returns all discovered immutable digests for an inventory
// item, including their evidence and the tag names that resolve to each digest.
func (s *Service) GetArtifactDigests(ctx context.Context, id int64) ([]*evidence.ArtifactDigest, error) {
	if s.evidenceSvc == nil {
		return nil, nil
	}
	return s.evidenceSvc.ListDigestsByItem(ctx, id)
}

// GetRepositoryTags returns all discovered mutable tags for an inventory item.
func (s *Service) GetRepositoryTags(ctx context.Context, id int64) ([]*evidence.RepositoryTag, error) {
	if s.evidenceSvc == nil {
		return nil, nil
	}
	return s.evidenceSvc.ListTagsByItem(ctx, id)
}

// GetDigestByID returns a single artifact digest with its evidence.
func (s *Service) GetDigestByID(ctx context.Context, digestID int64) (*evidence.ArtifactDigest, error) {
	if s.evidenceSvc == nil {
		return nil, nil
	}
	return s.evidenceSvc.GetDigestByID(ctx, digestID)
}

// GetSummaries returns a per-item discovery summary map for efficient display
// in the inventory list view.
func (s *Service) GetSummaries(ctx context.Context) (map[int64]*evidence.RepositorySummary, error) {
	if s.evidenceSvc == nil {
		return nil, nil
	}
	return s.evidenceSvc.GetSummaries(ctx)
}

func (s *Service) refreshEvidence(ctx context.Context, item *InventoryItem) error {
	user, role, team := infrolog.UserContextFields(ctx)
	if s.evidenceSvc == nil || item == nil {
		return nil
	}
	if err := s.evidenceSvc.RefreshRepository(ctx, evidence.DiscoveryTarget{
		InventoryItemID: item.ID,
		Registry:        item.Registry,
		Repository:      item.PackageName,
	}); err != nil {
		logError("inventory.refresh", user, role, team, item.ID, err)
		return err
	}
	slog.Info("inventory refresh complete",
		"operation", "inventory.refresh",
		"user", user,
		"role", role,
		"team", team,
		"inventory_item_id", item.ID,
	)
	return nil
}

func logError(operation, user, role, team string, inventoryItemID int64, err error) {
	slog.Error("unexpected inventory error",
		"operation", operation,
		"user", user,
		"role", role,
		"team", team,
		"inventory_item_id", inventoryItemID,
		"error", err.Error(),
	)
}
