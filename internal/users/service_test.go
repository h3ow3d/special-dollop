package users_test

import (
	"context"
	"testing"
	"time"

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
	var out []*users.User
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

type fakeRoleRepo struct {
	roles []*users.Role
}

func newFakeRoleRepo() *fakeRoleRepo {
	return &fakeRoleRepo{roles: []*users.Role{
		{ID: 1, Name: "Administrator", Slug: users.RoleSlugAdministrator},
		{ID: 2, Name: "Assessor", Slug: users.RoleSlugAssessor},
		{ID: 3, Name: "Reader", Slug: users.RoleSlugReader},
	}}
}

func (r *fakeRoleRepo) GetBySlug(_ context.Context, slug string) (*users.Role, error) {
	for _, role := range r.roles {
		if role.Slug == slug {
			return role, nil
		}
	}
	return nil, users.ErrNotFound
}

func (r *fakeRoleRepo) List(_ context.Context) ([]*users.Role, error) {
	return r.roles, nil
}

// ── tests ─────────────────────────────────────────────────────────────────────

func newTestService() *users.Service {
	return users.NewService(newFakeUserRepo(), newFakeRoleRepo())
}

func TestGetOrCreate_NewUser(t *testing.T) {
	svc := newTestService()
	u := &users.User{GitHubUserID: 42, GitHubUsername: "alice", DisplayName: "Alice", Email: "alice@example.com"}
	got, err := svc.GetOrCreate(context.Background(), u)
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	if got.ID == 0 {
		t.Fatal("expected non-zero ID")
	}
	if got.RoleID != 3 { // Reader role
		t.Fatalf("expected Reader role (3), got %d", got.RoleID)
	}
	if !got.Active {
		t.Fatal("new user should be active")
	}
}

func TestGetOrCreate_ExistingUser(t *testing.T) {
	svc := newTestService()
	u := &users.User{GitHubUserID: 42, GitHubUsername: "alice", DisplayName: "Alice"}
	first, _ := svc.GetOrCreate(context.Background(), u)

	// Second call with updated display name.
	u2 := &users.User{GitHubUserID: 42, GitHubUsername: "alice", DisplayName: "Alice Updated"}
	second, err := svc.GetOrCreate(context.Background(), u2)
	if err != nil {
		t.Fatalf("GetOrCreate second: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("expected same ID %d, got %d", first.ID, second.ID)
	}
	if second.DisplayName != "Alice Updated" {
		t.Fatalf("expected updated display name, got %q", second.DisplayName)
	}
}

func TestAssignRole(t *testing.T) {
	svc := newTestService()
	u := &users.User{GitHubUserID: 1, GitHubUsername: "bob"}
	created, _ := svc.GetOrCreate(context.Background(), u)

	if err := svc.AssignRole(context.Background(), created.ID, 1); err != nil { // Administrator
		t.Fatalf("AssignRole: %v", err)
	}
	got, _ := svc.GetByID(context.Background(), created.ID)
	if got.RoleID != 1 {
		t.Fatalf("expected roleID 1, got %d", got.RoleID)
	}
}

func TestSetActive(t *testing.T) {
	svc := newTestService()
	u := &users.User{GitHubUserID: 2, GitHubUsername: "carol"}
	created, _ := svc.GetOrCreate(context.Background(), u)

	if err := svc.SetActive(context.Background(), created.ID, false); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	got, _ := svc.GetByID(context.Background(), created.ID)
	if got.Active {
		t.Fatal("expected user to be inactive")
	}
}
