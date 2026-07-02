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
	count int
}

func (r *fakeAuditRepo) Record(_ context.Context, e *audit.Entry) error {
	r.count++
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
	svc := auth.NewService(userSvc, &fakeTeamRepo{}, auditSvc)

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
	svc := auth.NewService(userSvc, &fakeTeamRepo{}, auditSvc)

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
