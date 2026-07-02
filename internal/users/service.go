// Package users provides user management for the CDSCAM platform.
package users

import (
	"context"
	"fmt"
)

// Service provides user management operations.
type Service struct {
	users UserRepository
	roles RoleRepository
}

// NewService creates a UserService backed by the provided repositories.
func NewService(users UserRepository, roles RoleRepository) *Service {
	return &Service{users: users, roles: roles}
}

// GetOrCreate returns the existing user for the given GitHub user ID, or creates
// a new one with the "reader" role if none exists.
func (s *Service) GetOrCreate(ctx context.Context, u *User) (*User, error) {
	existing, err := s.users.GetByGitHubUserID(ctx, u.GitHubUserID)
	if err == nil {
		// Update display information but preserve role and team.
		existing.GitHubUsername = u.GitHubUsername
		existing.DisplayName = u.DisplayName
		existing.Email = u.Email
		existing.AvatarURL = u.AvatarURL
		if err := s.users.Upsert(ctx, existing); err != nil {
			return nil, fmt.Errorf("update user: %w", err)
		}
		return existing, nil
	}
	if err != ErrNotFound {
		return nil, fmt.Errorf("get user: %w", err)
	}

	// New user – assign Reader role by default.
	reader, err := s.roles.GetBySlug(ctx, RoleSlugReader)
	if err != nil {
		return nil, fmt.Errorf("get reader role: %w", err)
	}
	u.RoleID = reader.ID
	u.Active = true
	if err := s.users.Upsert(ctx, u); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// GetByID retrieves a user by their platform ID.
func (s *Service) GetByID(ctx context.Context, id int64) (*User, error) {
	return s.users.GetByID(ctx, id)
}

// List returns all platform users.
func (s *Service) List(ctx context.Context) ([]*User, error) {
	return s.users.List(ctx)
}

// ListRoles returns all roles.
func (s *Service) ListRoles(ctx context.Context) ([]*Role, error) {
	return s.roles.List(ctx)
}

// GetRoleBySlug returns a role by slug.
func (s *Service) GetRoleBySlug(ctx context.Context, slug string) (*Role, error) {
	return s.roles.GetBySlug(ctx, slug)
}

// AssignRole assigns a role to a user.
func (s *Service) AssignRole(ctx context.Context, userID, roleID int64) error {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	return s.users.UpdateRoleAndTeam(ctx, userID, roleID, u.TeamID)
}

// AssignTeam assigns a team to a user (nil removes the team).
func (s *Service) AssignTeam(ctx context.Context, userID int64, teamID *int64) error {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	return s.users.UpdateRoleAndTeam(ctx, userID, u.RoleID, teamID)
}

// SetActive activates or deactivates a user.
func (s *Service) SetActive(ctx context.Context, userID int64, active bool) error {
	return s.users.SetActive(ctx, userID, active)
}
