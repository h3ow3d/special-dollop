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
	created, _, err := s.GetOrCreateWithRole(ctx, u, RoleSlugReader)
	return created, err
}

// GetOrCreateWithRole returns the existing user for the given GitHub user ID,
// or creates a new one with the provided default role slug if none exists. The
// returned boolean reports whether a new user record was created.
func (s *Service) GetOrCreateWithRole(ctx context.Context, u *User, defaultRoleSlug string) (*User, bool, error) {
	existing, err := s.users.GetByGitHubUserID(ctx, u.GitHubUserID)
	if err == nil {
		// Update display information but preserve role and team.
		existing.GitHubUsername = u.GitHubUsername
		existing.DisplayName = u.DisplayName
		existing.Email = u.Email
		existing.AvatarURL = u.AvatarURL
		if err := s.users.Upsert(ctx, existing); err != nil {
			return nil, false, fmt.Errorf("update user: %w", err)
		}
		return existing, false, nil
	}
	if err != ErrNotFound {
		return nil, false, fmt.Errorf("get user: %w", err)
	}

	if defaultRoleSlug == "" {
		defaultRoleSlug = RoleSlugReader
	}

	role, err := s.roles.GetBySlug(ctx, defaultRoleSlug)
	if err != nil {
		return nil, false, fmt.Errorf("get %s role: %w", defaultRoleSlug, err)
	}
	u.RoleID = role.ID
	u.Active = true
	if err := s.users.Upsert(ctx, u); err != nil {
		return nil, false, fmt.Errorf("create user: %w", err)
	}
	return u, true, nil
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
