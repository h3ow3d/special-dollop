package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/securecookie"
	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/domain"
	"github.com/h3ow3d/special-dollop/internal/inventory"
	"github.com/h3ow3d/special-dollop/internal/teams"
	"github.com/h3ow3d/special-dollop/internal/users"
)

type testAdminUserRepo struct {
	users []*users.User
}

func (r *testAdminUserRepo) Upsert(_ context.Context, u *users.User) error { return nil }

func (r *testAdminUserRepo) GetByGitHubUserID(_ context.Context, githubUserID int64) (*users.User, error) {
	for _, user := range r.users {
		if user.GitHubUserID == githubUserID {
			cp := *user
			return &cp, nil
		}
	}
	return nil, users.ErrNotFound
}

func (r *testAdminUserRepo) GetByID(_ context.Context, id int64) (*users.User, error) {
	for _, user := range r.users {
		if user.ID == id {
			cp := *user
			return &cp, nil
		}
	}
	return nil, users.ErrNotFound
}

func (r *testAdminUserRepo) List(_ context.Context) ([]*users.User, error) {
	out := make([]*users.User, 0, len(r.users))
	for _, user := range r.users {
		cp := *user
		out = append(out, &cp)
	}
	return out, nil
}

func (r *testAdminUserRepo) UpdateRoleAndTeam(_ context.Context, userID, roleID int64, teamID *int64) error {
	return nil
}

func (r *testAdminUserRepo) SetActive(_ context.Context, userID int64, active bool) error {
	return nil
}

type testAdminRoleRepo struct{}

func (r *testAdminRoleRepo) GetBySlug(_ context.Context, slug string) (*users.Role, error) {
	for _, role := range testRoles() {
		if role.Slug == slug {
			cp := *role
			return &cp, nil
		}
	}
	return nil, users.ErrNotFound
}

func (r *testAdminRoleRepo) List(_ context.Context) ([]*users.Role, error) {
	return testRoles(), nil
}

type testAdminTeamRepo struct {
	teams []*teams.Team
}

func (r *testAdminTeamRepo) Create(_ context.Context, t *teams.Team) error { return nil }

func (r *testAdminTeamRepo) GetByID(_ context.Context, id int64) (*teams.Team, error) {
	for _, team := range r.teams {
		if team.ID == id {
			cp := *team
			return &cp, nil
		}
	}
	return nil, teams.ErrNotFound
}

func (r *testAdminTeamRepo) List(_ context.Context) ([]*teams.Team, error) {
	out := make([]*teams.Team, 0, len(r.teams))
	for _, team := range r.teams {
		cp := *team
		out = append(out, &cp)
	}
	return out, nil
}

func (r *testAdminTeamRepo) SetActive(_ context.Context, id int64, active bool) error { return nil }

type testAuditRepo struct{}

func (r *testAuditRepo) Record(_ context.Context, e *audit.Entry) error { return nil }

func (r *testAuditRepo) ListByUser(_ context.Context, userID int64, limit int) ([]*audit.Entry, error) {
	return nil, nil
}

// ── fake inventory repository ──────────────────────────────────────────────

type testInventoryRepo struct {
	items  []*inventory.InventoryItem
	nextID int64
}

func (r *testInventoryRepo) Create(_ context.Context, item *inventory.InventoryItem) error {
	r.nextID++
	item.ID = r.nextID
	item.CreatedAt = time.Now()
	item.UpdatedAt = time.Now()
	cp := *item
	r.items = append(r.items, &cp)
	return nil
}

func (r *testInventoryRepo) GetByID(_ context.Context, id int64) (*inventory.InventoryItem, error) {
	for _, item := range r.items {
		if item.ID == id {
			cp := *item
			return &cp, nil
		}
	}
	return nil, inventory.ErrNotFound
}

func (r *testInventoryRepo) Update(_ context.Context, item *inventory.InventoryItem) error {
	for i, existing := range r.items {
		if existing.ID == item.ID {
			cp := *item
			r.items[i] = &cp
			return nil
		}
	}
	return inventory.ErrNotFound
}

func (r *testInventoryRepo) SetActive(_ context.Context, id int64, active bool) error {
	for _, item := range r.items {
		if item.ID == id {
			item.Active = active
			return nil
		}
	}
	return inventory.ErrNotFound
}

func (r *testInventoryRepo) List(_ context.Context) ([]*inventory.InventoryItemWithTeam, error) {
	out := make([]*inventory.InventoryItemWithTeam, 0, len(r.items))
	for _, item := range r.items {
		cp := *item
		out = append(out, &inventory.InventoryItemWithTeam{InventoryItem: cp})
	}
	return out, nil
}

func (r *testInventoryRepo) ListByTeam(_ context.Context, teamID int64) ([]*inventory.InventoryItemWithTeam, error) {
	var out []*inventory.InventoryItemWithTeam
	for _, item := range r.items {
		if item.TeamID == teamID {
			cp := *item
			out = append(out, &inventory.InventoryItemWithTeam{InventoryItem: cp})
		}
	}
	return out, nil
}

func (r *testInventoryRepo) CountByTeam(_ context.Context) (map[int64]int, error) {
	counts := make(map[int64]int)
	for _, item := range r.items {
		if item.Active {
			counts[item.TeamID]++
		}
	}
	return counts, nil
}

func testRoles() []*users.Role {
	return []*users.Role{
		{ID: 1, Name: "Administrator", Slug: users.RoleSlugAdministrator},
		{ID: 2, Name: "Assessor", Slug: users.RoleSlugAssessor},
		{ID: 3, Name: "Reader", Slug: users.RoleSlugReader},
	}
}

func newRBACIntegrationHandler(t *testing.T) *Handler {
	t.Helper()

	h, _ := newTestHandler(t)
	teamID := int64(10)
	userSvc := users.NewService(&testAdminUserRepo{
		users: []*users.User{
			{
				ID:             1,
				GitHubUserID:   101,
				GitHubUsername: "admin",
				DisplayName:    "Admin User",
				Email:          "admin@example.com",
				RoleID:         1,
				TeamID:         &teamID,
				Active:         true,
			},
		},
	}, &testAdminRoleRepo{})
	teamSvc := teams.NewService(&testAdminTeamRepo{
		teams: []*teams.Team{
			{ID: 10, Name: "Platform", Active: true},
		},
	})
	auditSvc := audit.NewService(&testAuditRepo{})
	h.WithAdminHandler(NewAdminHandler(h, userSvc, teamSvc, auditSvc))

	inventorySvc := inventory.NewService(&testInventoryRepo{})
	h.WithInventoryHandler(NewInventoryHandler(h, inventorySvc, teamSvc, auditSvc))

	return h
}

func authenticatedRequest(t *testing.T, method, path, role string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, path, nil)
	sc := securecookie.New([]byte(testHashKey), nil)
	roleID := int64(3)
	switch role {
	case users.RoleSlugAdministrator:
		roleID = 1
	case users.RoleSlugAssessor:
		roleID = 2
	}
	teamID := int64(10)
	encoded, err := sc.Encode("clph_session", domain.UserSession{
		GitHubUser: domain.User{
			GitHubUsername: role,
			DisplayName:    role,
			Email:          role + "@example.com",
		},
		UserID:   roleID,
		RoleID:   roleID,
		RoleSlug: role,
		TeamID:   &teamID,
		TeamName: "Platform",
		Active:   true,
	})
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "clph_session", Value: encoded, Path: "/"})
	return req
}

func TestRBACIntegration_AdminUsersRoute(t *testing.T) {
	h := newRBACIntegrationHandler(t)
	router := h.Router([]byte("12345678901234567890123456789012"))

	t.Run("unauthenticated redirects", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rr.Code)
		}
		if location := rr.Header().Get("Location"); location != "/" {
			t.Fatalf("expected redirect to /, got %q", location)
		}
	})

	t.Run("reader forbidden", func(t *testing.T) {
		req := authenticatedRequest(t, http.MethodGet, "/admin/users", users.RoleSlugReader)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rr.Code)
		}
	})

	t.Run("assessor forbidden", func(t *testing.T) {
		req := authenticatedRequest(t, http.MethodGet, "/admin/users", users.RoleSlugAssessor)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rr.Code)
		}
	})

	t.Run("administrator allowed", func(t *testing.T) {
		req := authenticatedRequest(t, http.MethodGet, "/admin/users", users.RoleSlugAdministrator)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestRBACIntegration_AuthenticatedAccessByRole(t *testing.T) {
	h := newRBACIntegrationHandler(t)
	router := h.Router([]byte("12345678901234567890123456789012"))

	tests := []struct {
		name   string
		role   string
		method string
		path   string
		want   int
	}{
		{name: "reader profile page", role: users.RoleSlugReader, method: http.MethodGet, path: "/profile", want: http.StatusOK},
		{name: "reader inventory page", role: users.RoleSlugReader, method: http.MethodGet, path: "/oci/discover", want: http.StatusOK},
		{name: "reader assessments forbidden", role: users.RoleSlugReader, method: http.MethodGet, path: "/assessments", want: http.StatusForbidden},
		{name: "assessor assessments page", role: users.RoleSlugAssessor, method: http.MethodGet, path: "/assessments", want: http.StatusOK},
		{name: "assessor assessment page", role: users.RoleSlugAssessor, method: http.MethodGet, path: "/wizard/new", want: http.StatusOK},
		{name: "administrator teams page", role: users.RoleSlugAdministrator, method: http.MethodGet, path: "/admin/teams", want: http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := authenticatedRequest(t, tc.method, tc.path, tc.role)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("expected %d, got %d body=%s", tc.want, rr.Code, rr.Body.String())
			}
		})
	}
}

// ── Inventory RBAC tests ──────────────────────────────────────────────────────

func TestRBACIntegration_InventoryVisibility(t *testing.T) {
	h := newRBACIntegrationHandler(t)
	router := h.Router([]byte("12345678901234567890123456789012"))

	tests := []struct {
		name string
		role string
		want int
	}{
		{name: "reader can view inventory list", role: users.RoleSlugReader, want: http.StatusOK},
		{name: "assessor can view inventory list", role: users.RoleSlugAssessor, want: http.StatusOK},
		{name: "administrator can view inventory list", role: users.RoleSlugAdministrator, want: http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := authenticatedRequest(t, http.MethodGet, "/inventory", tc.role)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("expected %d, got %d body=%s", tc.want, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestRBACIntegration_InventoryCreateRoute(t *testing.T) {
	h := newRBACIntegrationHandler(t)
	router := h.Router([]byte("12345678901234567890123456789012"))

	t.Run("reader cannot access create form", func(t *testing.T) {
		req := authenticatedRequest(t, http.MethodGet, "/inventory/new", users.RoleSlugReader)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for reader on /inventory/new, got %d", rr.Code)
		}
	})

	t.Run("assessor can access create form", func(t *testing.T) {
		req := authenticatedRequest(t, http.MethodGet, "/inventory/new", users.RoleSlugAssessor)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for assessor on /inventory/new, got %d", rr.Code)
		}
	})

	t.Run("administrator can access create form", func(t *testing.T) {
		req := authenticatedRequest(t, http.MethodGet, "/inventory/new", users.RoleSlugAdministrator)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for administrator on /inventory/new, got %d", rr.Code)
		}
	})
}

func TestRBACIntegration_InventoryUnauthenticated(t *testing.T) {
	h := newRBACIntegrationHandler(t)
	router := h.Router([]byte("12345678901234567890123456789012"))

	paths := []string{"/inventory", "/inventory/new"}
	for _, path := range paths {
		t.Run("unauthenticated redirected from "+path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusFound {
				t.Fatalf("expected 302 redirect, got %d", rr.Code)
			}
		})
	}
}

func TestRBACIntegration_ReaderCannotStartAssessment(t *testing.T) {
	h := newRBACIntegrationHandler(t)
	router := h.Router([]byte("12345678901234567890123456789012"))

	t.Run("reader cannot access wizard/new", func(t *testing.T) {
		req := authenticatedRequest(t, http.MethodGet, "/wizard/new", users.RoleSlugReader)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for reader on /wizard/new, got %d", rr.Code)
		}
	})
}

// ── Team isolation helpers ────────────────────────────────────────────────────

const (
	platformTeamID     = int64(10)
	applicationsTeamID = int64(20)
)

// newIsolationTestHandler sets up a Handler with two teams (Platform=10,
// Applications=20) and one inventory item per team already seeded.
// It returns the handler and the platform item ID plus the applications item ID.
func newIsolationTestHandler(t *testing.T) (h *Handler, platformItemID, appsItemID int64) {
	t.Helper()
	h, _ = newTestHandler(t)

	teamRepo := &testAdminTeamRepo{
		teams: []*teams.Team{
			{ID: platformTeamID, Name: "Platform", Active: true},
			{ID: applicationsTeamID, Name: "Applications", Active: true},
		},
	}
	teamSvc := teams.NewService(teamRepo)

	invRepo := &testInventoryRepo{
		items: []*inventory.InventoryItem{
			{ID: 1, Name: "platform-item", TeamID: platformTeamID, Registry: "ghcr.io", Active: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
			{ID: 2, Name: "apps-item", TeamID: applicationsTeamID, Registry: "ghcr.io", Active: true, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		},
		nextID: 3, // next auto-increment value after the two seeded items
	}
	inventorySvc := inventory.NewService(invRepo)

	pID := int64(platformTeamID)
	userSvc := users.NewService(&testAdminUserRepo{
		users: []*users.User{{
			ID: 1, GitHubUserID: 101, GitHubUsername: "admin",
			DisplayName: "Admin User", RoleID: 1, TeamID: &pID, Active: true,
		}},
	}, &testAdminRoleRepo{})

	auditSvc := audit.NewService(&testAuditRepo{})
	h.WithAdminHandler(NewAdminHandler(h, userSvc, teamSvc, auditSvc))
	h.WithInventoryHandler(NewInventoryHandler(h, inventorySvc, teamSvc, auditSvc))

	return h, 1, 2
}

// authenticatedRequestForTeam creates an authenticated GET/POST request whose
// session carries the specified role and team. Pass teamID=0 to leave TeamID nil.
func authenticatedRequestForTeam(t *testing.T, method, path, role string, teamID int64, teamName string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	sc := securecookie.New([]byte(testHashKey), nil)
	roleID := int64(3)
	switch role {
	case users.RoleSlugAdministrator:
		roleID = 1
	case users.RoleSlugAssessor:
		roleID = 2
	}
	sess := domain.UserSession{
		GitHubUser: domain.User{
			GitHubUsername: role,
			DisplayName:    role,
			Email:          role + "@example.com",
		},
		UserID:   roleID,
		RoleID:   roleID,
		RoleSlug: role,
		TeamName: teamName,
		Active:   true,
	}
	if teamID > 0 {
		sess.TeamID = &teamID
	}
	encoded, err := sc.Encode("clph_session", sess)
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "clph_session", Value: encoded, Path: "/"})
	return req
}

// authenticatedFormPostForTeam creates a form-encoded POST request with an
// authenticated session for the specified role and team. CSRF is bypassed.
func authenticatedFormPostForTeam(t *testing.T, path, role string, teamID int64, teamName string, form url.Values) *http.Request {
	t.Helper()
	body := strings.NewReader(form.Encode())
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	sc := securecookie.New([]byte(testHashKey), nil)
	roleID := int64(3)
	switch role {
	case users.RoleSlugAdministrator:
		roleID = 1
	case users.RoleSlugAssessor:
		roleID = 2
	}
	sess := domain.UserSession{
		GitHubUser: domain.User{
			GitHubUsername: role,
			DisplayName:    role,
			Email:          role + "@example.com",
		},
		UserID:   roleID,
		RoleID:   roleID,
		RoleSlug: role,
		TeamName: teamName,
		Active:   true,
	}
	if teamID > 0 {
		sess.TeamID = &teamID
	}
	encoded, err := sc.Encode("clph_session", sess)
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "clph_session", Value: encoded, Path: "/"})
	return csrf.UnsafeSkipCheck(req)
}

// ── Inventory list isolation ──────────────────────────────────────────────────

func TestTeamIsolation_InventoryList(t *testing.T) {
	h, _, _ := newIsolationTestHandler(t)
	router := h.Router([]byte("12345678901234567890123456789012"))

	t.Run("reader sees only own team items", func(t *testing.T) {
		req := authenticatedRequestForTeam(t, http.MethodGet, "/inventory", users.RoleSlugReader, applicationsTeamID, "Applications")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if strings.Contains(body, "platform-item") {
			t.Fatal("reader from Applications should not see Platform team inventory")
		}
		if !strings.Contains(body, "apps-item") {
			t.Fatal("reader from Applications should see own team inventory")
		}
	})

	t.Run("assessor sees only own team items", func(t *testing.T) {
		req := authenticatedRequestForTeam(t, http.MethodGet, "/inventory", users.RoleSlugAssessor, applicationsTeamID, "Applications")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if strings.Contains(body, "platform-item") {
			t.Fatal("assessor from Applications should not see Platform team inventory")
		}
		if !strings.Contains(body, "apps-item") {
			t.Fatal("assessor from Applications should see own team inventory")
		}
	})

	t.Run("administrator sees all inventory", func(t *testing.T) {
		req := authenticatedRequestForTeam(t, http.MethodGet, "/inventory", users.RoleSlugAdministrator, 0, "")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if !strings.Contains(body, "platform-item") {
			t.Fatal("administrator should see Platform team inventory")
		}
		if !strings.Contains(body, "apps-item") {
			t.Fatal("administrator should see Applications team inventory")
		}
	})
}

// ── Inventory detail isolation ────────────────────────────────────────────────

func TestTeamIsolation_InventoryDetail(t *testing.T) {
	h, platformItemID, appsItemID := newIsolationTestHandler(t)
	router := h.Router([]byte("12345678901234567890123456789012"))

	platformPath := fmt.Sprintf("/inventory/%d", platformItemID)
	appsPath := fmt.Sprintf("/inventory/%d", appsItemID)

	t.Run("reader blocked from other team item", func(t *testing.T) {
		req := authenticatedRequestForTeam(t, http.MethodGet, platformPath, users.RoleSlugReader, applicationsTeamID, "Applications")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for reader accessing other team item, got %d", rr.Code)
		}
	})

	t.Run("assessor blocked from other team item", func(t *testing.T) {
		req := authenticatedRequestForTeam(t, http.MethodGet, platformPath, users.RoleSlugAssessor, applicationsTeamID, "Applications")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for assessor accessing other team item, got %d", rr.Code)
		}
	})

	t.Run("reader allowed own team item", func(t *testing.T) {
		req := authenticatedRequestForTeam(t, http.MethodGet, appsPath, users.RoleSlugReader, applicationsTeamID, "Applications")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for reader accessing own team item, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("assessor allowed own team item", func(t *testing.T) {
		req := authenticatedRequestForTeam(t, http.MethodGet, appsPath, users.RoleSlugAssessor, applicationsTeamID, "Applications")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for assessor accessing own team item, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("administrator allowed any item", func(t *testing.T) {
		for _, path := range []string{platformPath, appsPath} {
			req := authenticatedRequestForTeam(t, http.MethodGet, path, users.RoleSlugAdministrator, 0, "")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200 for administrator on %s, got %d body=%s", path, rr.Code, rr.Body.String())
			}
		}
	})
}

// ── Assessment creation authority ─────────────────────────────────────────────

func wizardForm(inventoryItemID int64) url.Values {
	f := url.Values{}
	f.Set("inventory_item_id", fmt.Sprintf("%d", inventoryItemID))
	f.Set("artefact_name", "test-artefact")
	f.Set("artefact_type", "application-container")
	f.Set("artefact_digest", "sha256:abc123def456")
	f.Set("artefact_registry", "ghcr.io")
	return f
}

func TestTeamIsolation_AssessmentCreation(t *testing.T) {
	h, platformItemID, appsItemID := newIsolationTestHandler(t)
	router := h.Router([]byte("12345678901234567890123456789012"))

	t.Run("assessor can assess own team inventory", func(t *testing.T) {
		req := authenticatedFormPostForTeam(t, "/wizard/new", users.RoleSlugAssessor, applicationsTeamID, "Applications", wizardForm(appsItemID))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		// Success → 302 redirect to wizard step 2.
		if rr.Code != http.StatusFound {
			t.Fatalf("expected 302 for assessor assessing own team item, got %d body=%s", rr.Code, rr.Body.String())
		}
		if !strings.HasPrefix(rr.Header().Get("Location"), "/wizard/") {
			t.Fatalf("expected redirect to /wizard/..., got %q", rr.Header().Get("Location"))
		}
	})

	t.Run("assessor cannot assess other team inventory", func(t *testing.T) {
		req := authenticatedFormPostForTeam(t, "/wizard/new", users.RoleSlugAssessor, applicationsTeamID, "Applications", wizardForm(platformItemID))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for assessor assessing other team item, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("administrator can assess any inventory item", func(t *testing.T) {
		for _, itemID := range []int64{platformItemID, appsItemID} {
			req := authenticatedFormPostForTeam(t, "/wizard/new", users.RoleSlugAdministrator, 0, "", wizardForm(itemID))
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusFound {
				t.Fatalf("expected 302 for administrator assessing item %d, got %d body=%s", itemID, rr.Code, rr.Body.String())
			}
		}
	})
}

// ── Inventory existence validation ────────────────────────────────────────────

func TestTeamIsolation_InventoryExistence(t *testing.T) {
	h, _, _ := newIsolationTestHandler(t)
	router := h.Router([]byte("12345678901234567890123456789012"))

	t.Run("non-existent inventory item returns 404", func(t *testing.T) {
		req := authenticatedFormPostForTeam(t, "/wizard/new", users.RoleSlugAdministrator, 0, "", wizardForm(9999))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for non-existent inventory item, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("missing inventory_item_id redirects to inventory", func(t *testing.T) {
		form := url.Values{}
		form.Set("artefact_name", "test")
		req := authenticatedFormPostForTeam(t, "/wizard/new", users.RoleSlugAssessor, platformTeamID, "Platform", form)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("expected 302 redirect for missing inventory_item_id, got %d", rr.Code)
		}
		if rr.Header().Get("Location") != "/inventory" {
			t.Fatalf("expected redirect to /inventory, got %q", rr.Header().Get("Location"))
		}
	})
}
