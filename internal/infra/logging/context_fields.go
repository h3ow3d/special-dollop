package logging

import (
	"context"

	"github.com/h3ow3d/special-dollop/internal/infra/security"
)

// UserContextFields returns session-derived user fields for structured logs.
func UserContextFields(ctx context.Context) (user, role, team string) {
	if session, ok := security.SessionFromContext(ctx); ok {
		return session.GitHubUser.GitHubUsername, session.EffectiveRoleSlug(), session.EffectiveTeamName()
	}
	return "", "", ""
}
