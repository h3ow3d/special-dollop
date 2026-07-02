package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/auth"
	"github.com/h3ow3d/special-dollop/internal/domain"
	"github.com/h3ow3d/special-dollop/internal/teams"
	"github.com/h3ow3d/special-dollop/internal/users"
)

// ── in-memory fakes ──────────────────────────────────────────────────────────

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
			now := time.Now().UTC()
			existing.LastLoginAt = &now
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

func (r *fakeUserRepo) List(_ context.Context) ([]*users.User, error) { return nil, nil }

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

type fakeTeamRepo struct{}

func (r *fakeTeamRepo) Create(_ context.Context, t *teams.Team) error        { return nil }
func (r *fakeTeamRepo) GetByID(_ context.Context, id int64) (*teams.Team, error) {
	return nil, teams.ErrNotFound
}
func (r *fakeTeamRepo) List(_ context.Context) ([]*teams.Team, error) { return nil, nil }
func (r *fakeTeamRepo) SetActive(_ context.Context, id int64, active bool) error { return nil }

type fakeAuditRepo struct {
	count   int
	entries []*audit.Entry
}

func (r *fakeAuditRepo) Record(_ context.Context, e *audit.Entry) error {
	r.count++
	cp := *e
	r.entries = append(r.entries, &cp)
	return nil
}

func (r *fakeAuditRepo) ListByUser(_ context.Context, userID int64, limit int) ([]*audit.Entry, error) {
	return nil, nil
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestEnrich_NewUser(t *testing.T) {
	auditRepo := &fakeAuditRepo{}
	auditSvc := audit.NewService(auditRepo)
	userSvc := users.NewService(newFakeUserRepo(), &fakeRoleRepo{})
	svc := auth.NewService(userSvc, &fakeTeamRepo{}, auditSvc, auth.Config{})

	gitHubUser := domain.User{
		GitHubUsername: "alice",
		DisplayName:    "Alice",
		Email:          "alice@example.com",
	}
	session, err := svc.Enrich(context.Background(), gitHubUser, 42, "127.0.0.1")
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if session.UserID == 0 {
		t.Fatal("expected non-zero UserID")
	}
	if session.RoleSlug != "reader" {
		t.Fatalf("expected reader role, got %q", session.RoleSlug)
	}
	if !session.Active {
		t.Fatal("expected session to be active")
	}
	if session.GitHubUser.GitHubUsername != "alice" {
		t.Fatalf("expected GitHub username alice, got %q", session.GitHubUser.GitHubUsername)
	}
	if auditRepo.count != 1 {
		t.Fatalf("expected 1 audit entry, got %d", auditRepo.count)
	}
}

func TestEnrich_DeactivatedUser(t *testing.T) {
	auditRepo := &fakeAuditRepo{}
	auditSvc := audit.NewService(auditRepo)
	userRepo := newFakeUserRepo()
	userSvc := users.NewService(userRepo, &fakeRoleRepo{})
	svc := auth.NewService(userSvc, &fakeTeamRepo{}, auditSvc, auth.Config{})

	// Create user first.
	_, _ = svc.Enrich(context.Background(), domain.User{GitHubUsername: "bob"}, 99, "")

	// Deactivate them.
	for _, u := range userRepo.store {
		u.Active = false
	}

	// Second login should fail.
	_, err := svc.Enrich(context.Background(), domain.User{GitHubUsername: "bob"}, 99, "")
	if err == nil {
		t.Fatal("expected error for deactivated user")
	}
}

func TestEnrich_BootstrapAdminAssignment(t *testing.T) {
	auditRepo := &fakeAuditRepo{}
	auditSvc := audit.NewService(auditRepo)
	userRepo := newFakeUserRepo()
	userSvc := users.NewService(userRepo, &fakeRoleRepo{})
	svc := auth.NewService(userSvc, &fakeTeamRepo{}, auditSvc, auth.Config{
		BootstrapAdmins: []string{"h3ow3d"},
	})

	session, err := svc.Enrich(context.Background(), domain.User{
		GitHubUsername: "h3Ow3D",
		DisplayName:    "H Three",
		Email:          "h3ow3d@example.com",
	}, 7, "127.0.0.1")
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if session.RoleSlug != users.RoleSlugAdministrator {
		t.Fatalf("expected administrator role, got %q", session.RoleSlug)
	}
	stored, err := userRepo.GetByID(context.Background(), session.UserID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if stored.RoleID != 1 {
		t.Fatalf("expected stored administrator role ID 1, got %d", stored.RoleID)
	}
	if len(auditRepo.entries) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(auditRepo.entries))
	}
	if auditRepo.entries[0].Action != audit.ActionBootstrapAdminAssigned {
		t.Fatalf("expected first audit action %q, got %q", audit.ActionBootstrapAdminAssigned, auditRepo.entries[0].Action)
	}
	if auditRepo.entries[1].Action != audit.ActionLogin {
		t.Fatalf("expected second audit action %q, got %q", audit.ActionLogin, auditRepo.entries[1].Action)
	}
}

func TestEnrich_NonBootstrapUserRemainsReader(t *testing.T) {
	auditRepo := &fakeAuditRepo{}
	auditSvc := audit.NewService(auditRepo)
	userSvc := users.NewService(newFakeUserRepo(), &fakeRoleRepo{})
	svc := auth.NewService(userSvc, &fakeTeamRepo{}, auditSvc, auth.Config{
		BootstrapAdmins: []string{"h3ow3d"},
	})

	session, err := svc.Enrich(context.Background(), domain.User{
		GitHubUsername: "alice",
		DisplayName:    "Alice",
		Email:          "alice@example.com",
	}, 8, "127.0.0.1")
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if session.RoleSlug != users.RoleSlugReader {
		t.Fatalf("expected reader role, got %q", session.RoleSlug)
	}
	if len(auditRepo.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(auditRepo.entries))
	}
	if auditRepo.entries[0].Action != audit.ActionLogin {
		t.Fatalf("expected login audit action, got %q", auditRepo.entries[0].Action)
	}
}

func TestEnrich_ExistingAdministratorNotDowngraded(t *testing.T) {
	auditRepo := &fakeAuditRepo{}
	auditSvc := audit.NewService(auditRepo)
	userRepo := newFakeUserRepo()
	userSvc := users.NewService(userRepo, &fakeRoleRepo{})
	svc := auth.NewService(userSvc, &fakeTeamRepo{}, auditSvc, auth.Config{})

	first, err := svc.Enrich(context.Background(), domain.User{GitHubUsername: "admin"}, 9, "")
	if err != nil {
		t.Fatalf("first Enrich: %v", err)
	}
	if err := userSvc.AssignRole(context.Background(), first.UserID, 1); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	second, err := svc.Enrich(context.Background(), domain.User{GitHubUsername: "admin"}, 9, "")
	if err != nil {
		t.Fatalf("second Enrich: %v", err)
	}
	if second.RoleSlug != users.RoleSlugAdministrator {
		t.Fatalf("expected administrator role, got %q", second.RoleSlug)
	}
}
