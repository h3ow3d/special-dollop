// Package auth provides the authentication service that bridges GitHub OAuth
// with the platform's persistent user model.
package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/domain"
	"github.com/h3ow3d/special-dollop/internal/teams"
	"github.com/h3ow3d/special-dollop/internal/users"
)

// Service enriches a GitHub OAuth identity with the platform's user record and
// RBAC state. It implements security.UserEnricher.
type Service struct {
	userSvc         *users.Service
	teamRepo        teams.Repository
	audit           *audit.Service
	bootstrapAdmins map[string]struct{}
}

// Config controls auth.Service runtime behavior.
type Config struct {
	BootstrapAdmins []string
}

// NewService creates an auth.Service with the required dependencies.
func NewService(userSvc *users.Service, teamRepo teams.Repository, audit *audit.Service, cfg Config) *Service {
	bootstrapAdmins := make(map[string]struct{}, len(cfg.BootstrapAdmins))
	for _, username := range cfg.BootstrapAdmins {
		username = strings.ToLower(strings.TrimSpace(username))
		if username == "" {
			continue
		}
		bootstrapAdmins[username] = struct{}{}
	}
	return &Service{
		userSvc:         userSvc,
		teamRepo:        teamRepo,
		audit:           audit,
		bootstrapAdmins: bootstrapAdmins,
	}
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

	defaultRoleSlug := users.RoleSlugReader
	if s.isBootstrapAdmin(gitHubUser.GitHubUsername) {
		defaultRoleSlug = users.RoleSlugAdministrator
	}

	platformUser, created, err := s.userSvc.GetOrCreateWithRole(ctx, u, defaultRoleSlug)
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
	if created && defaultRoleSlug == users.RoleSlugAdministrator {
		s.audit.Record(ctx, &id, audit.ActionBootstrapAdminAssigned,
			map[string]any{"github_username": gitHubUser.GitHubUsername, "role": users.RoleSlugAdministrator}, ip)
	}
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

func (s *Service) isBootstrapAdmin(username string) bool {
	_, ok := s.bootstrapAdmins[strings.ToLower(strings.TrimSpace(username))]
	return ok
}
