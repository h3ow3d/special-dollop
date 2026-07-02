// Package bootstrap provides dev login functionality when DEV_MODE=true.
package bootstrap

import (
	"context"
	"fmt"
	"time"

	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/domain"
	"github.com/h3ow3d/special-dollop/internal/teams"
	"github.com/h3ow3d/special-dollop/internal/users"
)

// AuthSourceDev is the AuthSource value stored in the session for dev logins.
const AuthSourceDev = "dev"

// LoginService creates authenticated sessions for development bootstrap users
// without going through GitHub OAuth. It must only be used when DEV_MODE=true.
type LoginService struct {
	userSvc  *users.Service
	teamRepo teams.Repository
	auditSvc *audit.Service
}

// NewLoginService creates a LoginService backed by the provided dependencies.
func NewLoginService(userSvc *users.Service, teamRepo teams.Repository, auditSvc *audit.Service) *LoginService {
	return &LoginService{
		userSvc:  userSvc,
		teamRepo: teamRepo,
		auditSvc: auditSvc,
	}
}

// Users returns the list of bootstrap dev users available for dev login.
func (s *LoginService) Users() []DevUserSpec {
	return BootstrapUsers
}

// CreateSession looks up the platform user matching the supplied dev username,
// builds a fully populated UserSession (identical in structure to a
// GitHub-authenticated session), records a dev.login audit event, and returns
// the session. The caller is responsible for persisting the session cookie.
func (s *LoginService) CreateSession(ctx context.Context, username, ip string) (domain.UserSession, error) {
	spec, ok := devUserByUsername(username)
	if !ok {
		return domain.UserSession{}, fmt.Errorf("unknown dev user: %q", username)
	}

	platformUser, err := s.userSvc.GetByGitHubUserID(ctx, spec.GitHubUserID)
	if err != nil {
		return domain.UserSession{}, fmt.Errorf("dev user not seeded: %w", err)
	}

	if !platformUser.Active {
		return domain.UserSession{}, fmt.Errorf("dev user account is deactivated")
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

	// Record dev login audit event.
	id := platformUser.ID
	s.auditSvc.Record(ctx, &id, audit.ActionDevLogin,
		map[string]any{"username": spec.Username, "display_name": spec.DisplayName}, ip)

	return domain.UserSession{
		GitHubUser: domain.User{
			GitHubUsername: spec.Username,
			DisplayName:    spec.DisplayName,
			Email:          spec.Email,
		},
		UserID:     platformUser.ID,
		RoleID:     platformUser.RoleID,
		RoleSlug:   roleSlug,
		TeamID:     platformUser.TeamID,
		TeamName:   teamName,
		AuthSource: AuthSourceDev,
		LoginAt:    time.Now().UTC(),
		Active:     platformUser.Active,
	}, nil
}

// devUserByUsername returns the DevUserSpec whose Username matches the supplied
// value, or (zero, false) if no match is found.
func devUserByUsername(username string) (DevUserSpec, bool) {
	for _, u := range BootstrapUsers {
		if u.Username == username {
			return u, true
		}
	}
	return DevUserSpec{}, false
}
