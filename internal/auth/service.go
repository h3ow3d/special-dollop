// Package auth provides the authentication service that bridges GitHub OAuth
// with the platform's persistent user model.
package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/domain"
	"github.com/h3ow3d/special-dollop/internal/teams"
	"github.com/h3ow3d/special-dollop/internal/users"
)

// Service enriches a GitHub OAuth identity with the platform's user record and
// RBAC state. It implements security.UserEnricher.
type Service struct {
	userSvc  *users.Service
	teamRepo teams.Repository
	audit    *audit.Service
}

// NewService creates an auth.Service with the required dependencies.
func NewService(userSvc *users.Service, teamRepo teams.Repository, audit *audit.Service) *Service {
	return &Service{userSvc: userSvc, teamRepo: teamRepo, audit: audit}
}

// Enrich looks up (or creates) the platform user for the given GitHub identity,
// records a login audit entry, and returns the populated UserSession.
func (s *Service) Enrich(ctx context.Context, gitHubUser domain.User, githubUserID int64, ip string) (domain.UserSession, error) {
	u := &users.User{
		GitHubUserID:   githubUserID,
		GitHubUsername: gitHubUser.GitHubUsername,
		DisplayName:    gitHubUser.DisplayName,
		Email:          gitHubUser.Email,
		AvatarURL:      gitHubUser.AvatarURL,
	}

	platformUser, err := s.userSvc.GetOrCreate(ctx, u)
	if err != nil {
		return domain.UserSession{}, fmt.Errorf("get or create user: %w", err)
	}

	if !platformUser.Active {
		return domain.UserSession{}, fmt.Errorf("account is deactivated")
	}

	// Resolve role slug.
	roles, err := s.userSvc.ListRoles(ctx)
	if err != nil {
		return domain.UserSession{}, fmt.Errorf("list roles: %w", err)
	}
	roleSlug := ""
	for _, r := range roles {
		if r.ID == platformUser.RoleID {
			roleSlug = r.Slug
			break
		}
	}

	// Resolve team name.
	teamName := ""
	if platformUser.TeamID != nil {
		if t, err := s.teamRepo.GetByID(ctx, *platformUser.TeamID); err == nil {
			teamName = t.Name
		}
	}

	// Record login audit event.
	id := platformUser.ID
	s.audit.Record(ctx, &id, audit.ActionLogin,
		map[string]any{"github_username": gitHubUser.GitHubUsername}, ip)

	return domain.UserSession{
		GitHubUser: gitHubUser,
		UserID:     platformUser.ID,
		RoleID:     platformUser.RoleID,
		RoleSlug:   roleSlug,
		TeamID:     platformUser.TeamID,
		TeamName:   teamName,
		LoginAt:    time.Now().UTC(),
		Active:     platformUser.Active,
	}, nil
}
