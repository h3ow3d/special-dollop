package inventory

import (
	"context"
	"fmt"
)

// Service provides inventory management operations.
type Service struct {
	repo Repository
}

// NewService creates a Service backed by the provided Repository.
func NewService(repo Repository) *Service { return &Service{repo: repo} }

// Create persists a new inventory item. The item's TeamID must be set by the
// caller; the service does not enforce team ownership rules.
func (s *Service) Create(ctx context.Context, item *InventoryItem) error {
	item.Active = true
	if err := s.repo.Create(ctx, item); err != nil {
		return fmt.Errorf("create inventory item: %w", err)
	}
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
	if err := s.repo.Update(ctx, item); err != nil {
		return fmt.Errorf("update inventory item: %w", err)
	}
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
