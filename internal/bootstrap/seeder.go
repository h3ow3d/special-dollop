// Package bootstrap provides idempotent seeding of development teams and users
// for the CDSCAM Assurance Platform. All functionality is gated behind DEV_MODE
// and must never be invoked in production.
package bootstrap

import (
	"context"
	"fmt"

	"github.com/h3ow3d/special-dollop/internal/teams"
	"github.com/h3ow3d/special-dollop/internal/users"
)

// DevTeamSpec describes a development team to be seeded.
type DevTeamSpec struct {
	Name        string
	Description string
}

// DevUserSpec describes a development user to be seeded. GitHubUserID uses a
// stable negative value that can never be issued by GitHub, ensuring dev users
// are cleanly separated from real GitHub-authenticated users.
type DevUserSpec struct {
	GitHubUserID int64  // stable negative sentinel; never a real GitHub user ID
	Username     string // used as github_username in the platform
	DisplayName  string
	Email        string
	RoleSlug     string
	TeamName     string
}

// BootstrapTeams is the ordered list of teams to seed when DEV_MODE=true.
var BootstrapTeams = []DevTeamSpec{
	{Name: "Platform Team", Description: "Platform engineering and shared services"},
	{Name: "Applications Team", Description: "Business applications and services"},
	{Name: "Security Team", Description: "Security tooling, governance and assurance"},
	{Name: "Data Team", Description: "Data platforms and analytics services"},
}

// BootstrapUsers is the ordered list of development users to seed when
// DEV_MODE=true. Usernames deliberately do not encode role or team information.
var BootstrapUsers = []DevUserSpec{
	{GitHubUserID: -1, Username: "sam.holden", DisplayName: "Sam Holden", Email: "sam.holden@dev.local", RoleSlug: users.RoleSlugAdministrator, TeamName: "Platform Team"},
	{GitHubUserID: -2, Username: "alex.carter", DisplayName: "Alex Carter", Email: "alex.carter@dev.local", RoleSlug: users.RoleSlugAssessor, TeamName: "Platform Team"},
	{GitHubUserID: -3, Username: "jordan.smith", DisplayName: "Jordan Smith", Email: "jordan.smith@dev.local", RoleSlug: users.RoleSlugReader, TeamName: "Platform Team"},
	{GitHubUserID: -4, Username: "taylor.brown", DisplayName: "Taylor Brown", Email: "taylor.brown@dev.local", RoleSlug: users.RoleSlugAssessor, TeamName: "Applications Team"},
	{GitHubUserID: -5, Username: "morgan.wilson", DisplayName: "Morgan Wilson", Email: "morgan.wilson@dev.local", RoleSlug: users.RoleSlugReader, TeamName: "Applications Team"},
	{GitHubUserID: -6, Username: "jamie.walker", DisplayName: "Jamie Walker", Email: "jamie.walker@dev.local", RoleSlug: users.RoleSlugReader, TeamName: "Applications Team"},
	{GitHubUserID: -7, Username: "casey.thomas", DisplayName: "Casey Thomas", Email: "casey.thomas@dev.local", RoleSlug: users.RoleSlugAssessor, TeamName: "Security Team"},
	{GitHubUserID: -8, Username: "riley.white", DisplayName: "Riley White", Email: "riley.white@dev.local", RoleSlug: users.RoleSlugReader, TeamName: "Security Team"},
	{GitHubUserID: -9, Username: "avery.green", DisplayName: "Avery Green", Email: "avery.green@dev.local", RoleSlug: users.RoleSlugAssessor, TeamName: "Data Team"},
	{GitHubUserID: -10, Username: "drew.hall", DisplayName: "Drew Hall", Email: "drew.hall@dev.local", RoleSlug: users.RoleSlugReader, TeamName: "Data Team"},
}

// Seeder idempotently seeds development teams and users into the platform
// database. It is safe to call Seed multiple times; existing records are
// not duplicated or overwritten.
type Seeder struct {
	teamSvc *teams.Service
	userSvc *users.Service
}

// NewSeeder creates a Seeder backed by the provided services.
func NewSeeder(teamSvc *teams.Service, userSvc *users.Service) *Seeder {
	return &Seeder{teamSvc: teamSvc, userSvc: userSvc}
}

// Seed creates any missing development teams and users. Existing records are
// left unchanged. Team assignments are only set when a user does not yet have
// a team, preserving any manual reassignments made after first boot.
func (s *Seeder) Seed(ctx context.Context) error {
	// Seed teams and build a name→Team index.
	teamIndex := make(map[string]*teams.Team, len(BootstrapTeams))
	for _, spec := range BootstrapTeams {
		t, err := s.teamSvc.GetOrCreate(ctx, spec.Name, spec.Description)
		if err != nil {
			return fmt.Errorf("seed team %q: %w", spec.Name, err)
		}
		teamIndex[spec.Name] = t
	}

	// Seed users.
	for _, spec := range BootstrapUsers {
		u := &users.User{
			GitHubUserID:   spec.GitHubUserID,
			GitHubUsername: spec.Username,
			DisplayName:    spec.DisplayName,
			Email:          spec.Email,
		}
		platformUser, created, err := s.userSvc.GetOrCreateWithRole(ctx, u, spec.RoleSlug)
		if err != nil {
			return fmt.Errorf("seed user %q: %w", spec.Username, err)
		}

		// Assign team only if the user was just created or has no team yet.
		if created || platformUser.TeamID == nil {
			team, ok := teamIndex[spec.TeamName]
			if !ok {
				return fmt.Errorf("seed user %q: team %q not found after seeding", spec.Username, spec.TeamName)
			}
			if err := s.userSvc.AssignTeam(ctx, platformUser.ID, &team.ID); err != nil {
				return fmt.Errorf("seed user %q assign team: %w", spec.Username, err)
			}
		}
	}
	return nil
}
