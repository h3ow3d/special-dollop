// Package bootstrap provides idempotent seeding of development teams and users
// for the CDSCAM Assurance Platform. All functionality is gated behind DEV_MODE
// and must never be invoked in production.
package bootstrap

import (
	"context"
	"fmt"

	"github.com/h3ow3d/special-dollop/internal/inventory"
	"github.com/h3ow3d/special-dollop/internal/teams"
	"github.com/h3ow3d/special-dollop/internal/users"
)

// DevTeamSpec describes a development team to be seeded.
type DevTeamSpec struct {
	Name        string
	Description string
}

// DevUserSpec describes a development user to be seeded. GitHubUserID uses a
// stable negative value: GitHub only ever issues positive integer user IDs, so
// negative values are a safe sentinel range that can never conflict with real
// GitHub-authenticated users. This allows the existing GetByGitHubUserID lookup
// path to work without additional repository methods.
type DevUserSpec struct {
	GitHubUserID int64  // stable negative sentinel; GitHub IDs are always positive
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

// BootstrapInventory is the ordered list of inventory items to seed when
// DEV_MODE=true. Items are associated with a team by name.
var BootstrapInventory = []struct {
	Name          string
	Description   string
	TeamName      string
	Registry      string
	Reference     string
	PackageURL    string
	PackageName   string
	RepositoryURL string
}{
	{
		Name: "proverjay", TeamName: "Platform Team", Registry: "ghcr.io",
		Reference:     "latest",
		PackageName:   "h3ow3d/proverjay",
		PackageURL:    "https://github.com/h3ow3d/proverjay/pkgs/container/proverjay",
		RepositoryURL: "https://github.com/h3ow3d/proverjay",
		Description:   "Provenance verification tooling for GHCR packages.",
	},
	{
		Name: "harbor", TeamName: "Platform Team", Registry: "ghcr.io",
		Reference:     "latest",
		PackageName:   "goharbor/harbor",
		PackageURL:    "https://github.com/goharbor/harbor/pkgs/container/harbor",
		RepositoryURL: "https://github.com/goharbor/harbor",
		Description:   "Cloud-native container registry.",
	},
	{
		Name: "cert-manager", TeamName: "Platform Team", Registry: "quay.io",
		Reference:     "latest",
		PackageName:   "jetstack/cert-manager-controller",
		PackageURL:    "https://quay.io/repository/jetstack/cert-manager-controller",
		RepositoryURL: "https://github.com/cert-manager/cert-manager",
		Description:   "X.509 certificate management for Kubernetes.",
	},
	{
		Name: "customer-portal", TeamName: "Applications Team", Registry: "ghcr.io",
		Reference:     "latest",
		PackageName:   "h3ow3d/customer-portal",
		PackageURL:    "https://github.com/h3ow3d/customer-portal/pkgs/container/customer-portal",
		RepositoryURL: "https://github.com/h3ow3d/customer-portal",
		Description:   "Customer-facing web portal.",
	},
	{
		Name: "orders-api", TeamName: "Applications Team", Registry: "ghcr.io",
		Reference:     "latest",
		PackageName:   "h3ow3d/orders-api",
		PackageURL:    "https://github.com/h3ow3d/orders-api/pkgs/container/orders-api",
		RepositoryURL: "https://github.com/h3ow3d/orders-api",
		Description:   "REST API for order processing.",
	},
	{
		Name: "trivy", TeamName: "Security Team", Registry: "ghcr.io",
		Reference:     "latest",
		PackageName:   "aquasecurity/trivy",
		PackageURL:    "https://github.com/aquasecurity/trivy/pkgs/container/trivy",
		RepositoryURL: "https://github.com/aquasecurity/trivy",
		Description:   "Vulnerability scanner for containers and filesystems.",
	},
	{
		Name: "falco", TeamName: "Security Team", Registry: "docker.io",
		Reference:     "latest",
		PackageName:   "falcosecurity/falco",
		PackageURL:    "https://hub.docker.com/r/falcosecurity/falco",
		RepositoryURL: "https://github.com/falcosecurity/falco",
		Description:   "Cloud-native runtime security.",
	},
	{
		Name: "analytics-worker", TeamName: "Data Team", Registry: "ghcr.io",
		Reference:     "latest",
		PackageName:   "h3ow3d/analytics-worker",
		PackageURL:    "https://github.com/h3ow3d/analytics-worker/pkgs/container/analytics-worker",
		RepositoryURL: "https://github.com/h3ow3d/analytics-worker",
		Description:   "Background worker for analytics pipeline processing.",
	},
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
	teamSvc      *teams.Service
	userSvc      *users.Service
	inventorySvc *inventory.Service
}

// NewSeeder creates a Seeder backed by the provided services.
func NewSeeder(teamSvc *teams.Service, userSvc *users.Service, inventorySvc *inventory.Service) *Seeder {
	return &Seeder{teamSvc: teamSvc, userSvc: userSvc, inventorySvc: inventorySvc}
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

	// Seed inventory items when the inventory service is available.
	if s.inventorySvc != nil {
		// Fetch all existing inventory items once and build an in-memory index
		// by (team_id, name) to avoid N+1 queries during idempotency checks.
		allItems, err := s.inventorySvc.List(ctx)
		if err != nil {
			return fmt.Errorf("seed inventory: list existing: %w", err)
		}
		type teamName struct {
			teamID int64
			name   string
		}
		existingIndex := make(map[teamName]bool, len(allItems))
		for _, item := range allItems {
			existingIndex[teamName{item.TeamID, item.Name}] = true
		}

		for _, spec := range BootstrapInventory {
			team, ok := teamIndex[spec.TeamName]
			if !ok {
				return fmt.Errorf("seed inventory %q: team %q not found", spec.Name, spec.TeamName)
			}
			if existingIndex[teamName{team.ID, spec.Name}] {
				continue
			}
			item := &inventory.InventoryItem{
				Name:          spec.Name,
				Description:   spec.Description,
				TeamID:        team.ID,
				Registry:      spec.Registry,
				Reference:     spec.Reference,
				PackageURL:    spec.PackageURL,
				PackageName:   spec.PackageName,
				RepositoryURL: spec.RepositoryURL,
			}
			if err := s.inventorySvc.Create(ctx, item); err != nil {
				return fmt.Errorf("seed inventory %q: %w", spec.Name, err)
			}
			existingIndex[teamName{team.ID, spec.Name}] = true
		}
	}

	return nil
}