package teams

import (
	"context"
	"fmt"
)

// Service provides team management operations.
type Service struct {
	repo Repository
}

// NewService creates a Service backed by the provided Repository.
func NewService(repo Repository) *Service { return &Service{repo: repo} }

// GetOrCreate returns the existing team with the given name, or creates a new
// one if no team with that name exists. It is safe to call multiple times.
func (s *Service) GetOrCreate(ctx context.Context, name, description string) (*Team, error) {
	ts, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list teams: %w", err)
	}
	for _, t := range ts {
		if t.Name == name {
			return t, nil
		}
	}
	return s.Create(ctx, name, description)
}

// Create persists a new team.
func (s *Service) Create(ctx context.Context, name, description string) (*Team, error) {
	t := &Team{Name: name, Description: description, Active: true}
	if err := s.repo.Create(ctx, t); err != nil {
		return nil, fmt.Errorf("create team: %w", err)
	}
	return t, nil
}

// GetByID retrieves a team by its ID.
func (s *Service) GetByID(ctx context.Context, id int64) (*Team, error) {
	return s.repo.GetByID(ctx, id)
}

// List returns all teams.
func (s *Service) List(ctx context.Context) ([]*Team, error) {
	return s.repo.List(ctx)
}

// SetActive activates or deactivates a team.
func (s *Service) SetActive(ctx context.Context, id int64, active bool) error {
	return s.repo.SetActive(ctx, id, active)
}
