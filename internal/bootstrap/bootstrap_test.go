package bootstrap_test

import (
	"context"
	"testing"
	"time"

	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/bootstrap"
	"github.com/h3ow3d/special-dollop/internal/teams"
	"github.com/h3ow3d/special-dollop/internal/users"
)

// ── in-memory fakes ──────────────────────────────────────────────────────────

type fakeTeamRepo struct {
	store  map[int64]*teams.Team
	nextID int64
}

func newFakeTeamRepo() *fakeTeamRepo {
	return &fakeTeamRepo{store: make(map[int64]*teams.Team), nextID: 1}
}

func (r *fakeTeamRepo) Create(_ context.Context, t *teams.Team) error {
	t.ID = r.nextID
	r.nextID++
	cp := *t
	r.store[t.ID] = &cp
	return nil
}

func (r *fakeTeamRepo) GetByID(_ context.Context, id int64) (*teams.Team, error) {
	t, ok := r.store[id]
	if !ok {
		return nil, teams.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (r *fakeTeamRepo) List(_ context.Context) ([]*teams.Team, error) {
	out := make([]*teams.Team, 0, len(r.store))
	for _, t := range r.store {
		cp := *t
		out = append(out, &cp)
	}
	return out, nil
}

func (r *fakeTeamRepo) SetActive(_ context.Context, id int64, active bool) error {
	t, ok := r.store[id]
	if !ok {
		return teams.ErrNotFound
	}
	t.Active = active
	return nil
}

type fakeUserRepo struct {
	store  map[int64]*users.User
	nextID int64
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{store: make(map[int64]*users.User), nextID: 1}
}

func (r *fakeUserRepo) Upsert(_ context.Context, u *users.User) error {
	for _, existing := range r.store {
		if existing.GitHubUserID == u.GitHubUserID {
			existing.GitHubUsername = u.GitHubUsername
			existing.DisplayName = u.DisplayName
			existing.Email = u.Email
			existing.AvatarURL = u.AvatarURL
			now := time.Now().UTC()
			existing.LastLoginAt = &now
			existing.UpdatedAt = now
			*u = *existing
			return nil
		}
	}
	u.ID = r.nextID
	r.nextID++
	u.CreatedAt = time.Now().UTC()
	u.UpdatedAt = u.CreatedAt
	cp := *u
	r.store[u.ID] = &cp
	return nil
}

func (r *fakeUserRepo) GetByGitHubUserID(_ context.Context, id int64) (*users.User, error) {
	for _, u := range r.store {
		if u.GitHubUserID == id {
			cp := *u
			return &cp, nil
		}
	}
	return nil, users.ErrNotFound
}

func (r *fakeUserRepo) GetByID(_ context.Context, id int64) (*users.User, error) {
	u, ok := r.store[id]
	if !ok {
		return nil, users.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (r *fakeUserRepo) List(_ context.Context) ([]*users.User, error) {
	out := make([]*users.User, 0, len(r.store))
	for _, u := range r.store {
		cp := *u
		out = append(out, &cp)
	}
	return out, nil
}

func (r *fakeUserRepo) UpdateRoleAndTeam(_ context.Context, userID, roleID int64, teamID *int64) error {
	u, ok := r.store[userID]
	if !ok {
		return users.ErrNotFound
	}
	u.RoleID = roleID
	u.TeamID = teamID
	return nil
}

func (r *fakeUserRepo) SetActive(_ context.Context, userID int64, active bool) error {
	u, ok := r.store[userID]
	if !ok {
		return users.ErrNotFound
	}
	u.Active = active
	return nil
}

type fakeRoleRepo struct{}

func (r *fakeRoleRepo) GetBySlug(_ context.Context, slug string) (*users.Role, error) {
	roles := map[string]*users.Role{
		"administrator": {ID: 1, Name: "Administrator", Slug: "administrator"},
		"assessor":      {ID: 2, Name: "Assessor", Slug: "assessor"},
		"reader":        {ID: 3, Name: "Reader", Slug: "reader"},
	}
	if role, ok := roles[slug]; ok {
		return role, nil
	}
	return nil, users.ErrNotFound
}

func (r *fakeRoleRepo) List(_ context.Context) ([]*users.Role, error) {
	return []*users.Role{
		{ID: 1, Name: "Administrator", Slug: "administrator"},
		{ID: 2, Name: "Assessor", Slug: "assessor"},
		{ID: 3, Name: "Reader", Slug: "reader"},
	}, nil
}

type fakeAuditRepo struct {
	entries []*audit.Entry
}

func (r *fakeAuditRepo) Record(_ context.Context, e *audit.Entry) error {
	cp := *e
	r.entries = append(r.entries, &cp)
	return nil
}

func (r *fakeAuditRepo) ListByUser(_ context.Context, userID int64, limit int) ([]*audit.Entry, error) {
	return nil, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func newTestDeps(t *testing.T) (*fakeTeamRepo, *fakeUserRepo, *fakeAuditRepo, *teams.Service, *users.Service, *audit.Service) {
	t.Helper()
	teamRepo := newFakeTeamRepo()
	userRepo := newFakeUserRepo()
	auditRepo := &fakeAuditRepo{}
	teamSvc := teams.NewService(teamRepo)
	userSvc := users.NewService(userRepo, &fakeRoleRepo{})
	auditSvc := audit.NewService(auditRepo)
	return teamRepo, userRepo, auditRepo, teamSvc, userSvc, auditSvc
}

// ── bootstrap seeder tests ────────────────────────────────────────────────────

func TestSeed_CreatesTeams(t *testing.T) {
	teamRepo, _, _, teamSvc, userSvc, _ := newTestDeps(t)
	seeder := bootstrap.NewSeeder(teamSvc, userSvc)

	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	if got, want := len(teamRepo.store), len(bootstrap.BootstrapTeams); got != want {
		t.Fatalf("expected %d teams, got %d", want, got)
	}
}

func TestSeed_TeamNames(t *testing.T) {
	_, _, _, teamSvc, userSvc, _ := newTestDeps(t)
	seeder := bootstrap.NewSeeder(teamSvc, userSvc)

	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	ts, _ := teamSvc.List(context.Background())
	nameSet := make(map[string]bool, len(ts))
	for _, t := range ts {
		nameSet[t.Name] = true
	}
	for _, spec := range bootstrap.BootstrapTeams {
		if !nameSet[spec.Name] {
			t.Errorf("expected team %q to be seeded", spec.Name)
		}
	}
}

func TestSeed_CreatesUsers(t *testing.T) {
	_, userRepo, _, teamSvc, userSvc, _ := newTestDeps(t)
	seeder := bootstrap.NewSeeder(teamSvc, userSvc)

	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	if got, want := len(userRepo.store), len(bootstrap.BootstrapUsers); got != want {
		t.Fatalf("expected %d users, got %d", want, got)
	}
}

func TestSeed_Idempotent_Teams(t *testing.T) {
	teamRepo, _, _, teamSvc, userSvc, _ := newTestDeps(t)
	seeder := bootstrap.NewSeeder(teamSvc, userSvc)

	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("first Seed: %v", err)
	}
	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("second Seed: %v", err)
	}

	if got, want := len(teamRepo.store), len(bootstrap.BootstrapTeams); got != want {
		t.Fatalf("expected %d teams after double seed, got %d", want, got)
	}
}

func TestSeed_Idempotent_Users(t *testing.T) {
	_, userRepo, _, teamSvc, userSvc, _ := newTestDeps(t)
	seeder := bootstrap.NewSeeder(teamSvc, userSvc)

	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("first Seed: %v", err)
	}
	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("second Seed: %v", err)
	}

	if got, want := len(userRepo.store), len(bootstrap.BootstrapUsers); got != want {
		t.Fatalf("expected %d users after double seed, got %d", want, got)
	}
}

func TestSeed_RoleAssignment(t *testing.T) {
	_, userRepo, _, teamSvc, userSvc, _ := newTestDeps(t)
	seeder := bootstrap.NewSeeder(teamSvc, userSvc)

	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	// Build expected role assignments from spec.
	expectedRoles := map[string]int64{
		users.RoleSlugAdministrator: 1,
		users.RoleSlugAssessor:      2,
		users.RoleSlugReader:        3,
	}

	for _, spec := range bootstrap.BootstrapUsers {
		var found *users.User
		for _, u := range userRepo.store {
			if u.GitHubUsername == spec.Username {
				found = u
				break
			}
		}
		if found == nil {
			t.Errorf("user %q not found after seeding", spec.Username)
			continue
		}
		wantRoleID := expectedRoles[spec.RoleSlug]
		if found.RoleID != wantRoleID {
			t.Errorf("user %q: expected role ID %d (%s), got %d", spec.Username, wantRoleID, spec.RoleSlug, found.RoleID)
		}
	}
}

func TestSeed_TeamAssignment(t *testing.T) {
	_, userRepo, _, teamSvc, userSvc, _ := newTestDeps(t)
	seeder := bootstrap.NewSeeder(teamSvc, userSvc)

	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	ts, _ := teamSvc.List(context.Background())
	teamByID := make(map[int64]string, len(ts))
	for _, t := range ts {
		teamByID[t.ID] = t.Name
	}

	for _, spec := range bootstrap.BootstrapUsers {
		var found *users.User
		for _, u := range userRepo.store {
			if u.GitHubUsername == spec.Username {
				found = u
				break
			}
		}
		if found == nil {
			t.Errorf("user %q not found after seeding", spec.Username)
			continue
		}
		if found.TeamID == nil {
			t.Errorf("user %q has no team assigned", spec.Username)
			continue
		}
		if got := teamByID[*found.TeamID]; got != spec.TeamName {
			t.Errorf("user %q: expected team %q, got %q", spec.Username, spec.TeamName, got)
		}
	}
}

func TestSeed_PreservesExistingTeamOnRerun(t *testing.T) {
	_, userRepo, _, teamSvc, userSvc, _ := newTestDeps(t)
	seeder := bootstrap.NewSeeder(teamSvc, userSvc)

	// First seed
	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("first Seed: %v", err)
	}

	// Manually move sam.holden to a different team.
	ts, _ := teamSvc.List(context.Background())
	var applicationsTeamID int64
	for _, t := range ts {
		if t.Name == "Applications Team" {
			applicationsTeamID = t.ID
			break
		}
	}
	var samID int64
	for _, u := range userRepo.store {
		if u.GitHubUsername == "sam.holden" {
			samID = u.ID
			break
		}
	}
	if err := userSvc.AssignTeam(context.Background(), samID, &applicationsTeamID); err != nil {
		t.Fatalf("AssignTeam: %v", err)
	}

	// Second seed should not overwrite the manual assignment.
	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("second Seed: %v", err)
	}

	sam, _ := userSvc.GetByID(context.Background(), samID)
	if sam.TeamID == nil || *sam.TeamID != applicationsTeamID {
		t.Fatalf("expected manually assigned team to be preserved after re-seed")
	}
}

// ── dev login service tests ───────────────────────────────────────────────────

func TestDevLoginService_CreateSession(t *testing.T) {
	teamRepo, _, _, teamSvc, userSvc, auditSvc := newTestDeps(t)
	seeder := bootstrap.NewSeeder(teamSvc, userSvc)
	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	loginSvc := bootstrap.NewLoginService(userSvc, teamRepo, auditSvc)
	session, err := loginSvc.CreateSession(context.Background(), "sam.holden", "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if session.UserID == 0 {
		t.Fatal("expected non-zero UserID")
	}
	if session.RoleSlug != users.RoleSlugAdministrator {
		t.Fatalf("expected administrator role, got %q", session.RoleSlug)
	}
	if !session.Active {
		t.Fatal("expected session to be active")
	}
	if session.GitHubUser.DisplayName != "Sam Holden" {
		t.Fatalf("expected display name Sam Holden, got %q", session.GitHubUser.DisplayName)
	}
	if session.AuthSource != bootstrap.AuthSourceDev {
		t.Fatalf("expected AuthSource %q, got %q", bootstrap.AuthSourceDev, session.AuthSource)
	}
}

func TestDevLoginService_RecordsAuditEvent(t *testing.T) {
	teamRepo, _, auditRepo, teamSvc, userSvc, auditSvc := newTestDeps(t)
	seeder := bootstrap.NewSeeder(teamSvc, userSvc)
	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	loginSvc := bootstrap.NewLoginService(userSvc, teamRepo, auditSvc)
	_, err := loginSvc.CreateSession(context.Background(), "sam.holden", "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if len(auditRepo.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(auditRepo.entries))
	}
	if auditRepo.entries[0].Action != audit.ActionDevLogin {
		t.Fatalf("expected action %q, got %q", audit.ActionDevLogin, auditRepo.entries[0].Action)
	}
}

func TestDevLoginService_TeamName(t *testing.T) {
	teamRepo, _, _, teamSvc, userSvc, auditSvc := newTestDeps(t)
	seeder := bootstrap.NewSeeder(teamSvc, userSvc)
	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	loginSvc := bootstrap.NewLoginService(userSvc, teamRepo, auditSvc)

	tests := []struct {
		username string
		wantTeam string
	}{
		{"sam.holden", "Platform Team"},
		{"taylor.brown", "Applications Team"},
		{"casey.thomas", "Security Team"},
		{"drew.hall", "Data Team"},
	}
	for _, tc := range tests {
		session, err := loginSvc.CreateSession(context.Background(), tc.username, "")
		if err != nil {
			t.Fatalf("CreateSession %q: %v", tc.username, err)
		}
		if session.TeamName != tc.wantTeam {
			t.Errorf("user %q: expected team %q, got %q", tc.username, tc.wantTeam, session.TeamName)
		}
	}
}

func TestDevLoginService_UnknownUser(t *testing.T) {
	teamRepo, _, _, _, userSvc, auditSvc := newTestDeps(t)
	loginSvc := bootstrap.NewLoginService(userSvc, teamRepo, auditSvc)

	_, err := loginSvc.CreateSession(context.Background(), "unknown.user", "127.0.0.1")
	if err == nil {
		t.Fatal("expected error for unknown username")
	}
}

func TestDevLoginService_UnseededUser(t *testing.T) {
	teamRepo, _, _, _, userSvc, auditSvc := newTestDeps(t)
	// Do NOT call Seed — users are not in the DB.
	loginSvc := bootstrap.NewLoginService(userSvc, teamRepo, auditSvc)

	_, err := loginSvc.CreateSession(context.Background(), "sam.holden", "127.0.0.1")
	if err == nil {
		t.Fatal("expected error when bootstrap user has not been seeded")
	}
}

func TestDevLoginService_AllUsersSessionCreation(t *testing.T) {
	teamRepo, _, _, teamSvc, userSvc, auditSvc := newTestDeps(t)
	seeder := bootstrap.NewSeeder(teamSvc, userSvc)
	if err := seeder.Seed(context.Background()); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	loginSvc := bootstrap.NewLoginService(userSvc, teamRepo, auditSvc)
	for _, spec := range bootstrap.BootstrapUsers {
		session, err := loginSvc.CreateSession(context.Background(), spec.Username, "")
		if err != nil {
			t.Errorf("CreateSession %q: %v", spec.Username, err)
			continue
		}
		if session.RoleSlug != spec.RoleSlug {
			t.Errorf("user %q: expected role %q, got %q", spec.Username, spec.RoleSlug, session.RoleSlug)
		}
		if session.TeamName != spec.TeamName {
			t.Errorf("user %q: expected team %q, got %q", spec.Username, spec.TeamName, session.TeamName)
		}
		if session.AuthSource != bootstrap.AuthSourceDev {
			t.Errorf("user %q: expected AuthSource %q, got %q", spec.Username, bootstrap.AuthSourceDev, session.AuthSource)
		}
	}
}
