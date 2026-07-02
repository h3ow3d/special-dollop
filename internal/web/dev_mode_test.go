package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/securecookie"
	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/domain"
	"github.com/h3ow3d/special-dollop/internal/infra/security"
	"github.com/h3ow3d/special-dollop/internal/teams"
	"github.com/h3ow3d/special-dollop/internal/users"
)

type capturingAuditRepo struct {
	entries []*audit.Entry
}

func (r *capturingAuditRepo) Record(_ context.Context, e *audit.Entry) error {
	cp := *e
	r.entries = append(r.entries, &cp)
	return nil
}

func (r *capturingAuditRepo) ListByUser(_ context.Context, userID int64, limit int) ([]*audit.Entry, error) {
	return nil, nil
}

func newDevModeHandler(t *testing.T, enabled bool) (*Handler, *security.OAuthHandler, *testAdminUserRepo, *capturingAuditRepo) {
	t.Helper()

	h, oauth := newTestHandler(t)
	h.WithDevelopmentMode(enabled)

	teamID := int64(10)
	userRepo := &testAdminUserRepo{
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
			{
				ID:             2,
				GitHubUserID:   102,
				GitHubUsername: "reader",
				DisplayName:    "Reader User",
				Email:          "reader@example.com",
				RoleID:         3,
				Active:         true,
			},
		},
	}
	teamSvc := teams.NewService(&testAdminTeamRepo{
		teams: []*teams.Team{
			{ID: 10, Name: "Platform", Active: true},
		},
	})
	auditRepo := &capturingAuditRepo{}
	userSvc := users.NewService(userRepo, &testAdminRoleRepo{})
	auditSvc := audit.NewService(auditRepo)
	h.WithAdminHandler(NewAdminHandler(h, userSvc, teamSvc, auditSvc))

	return h, oauth, userRepo, auditRepo
}

func newSessionRequest(t *testing.T, method, target string, session domain.UserSession, body string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	sc := securecookie.New([]byte(testHashKey), nil)
	encoded, err := sc.Encode("clph_session", session)
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "clph_session", Value: encoded, Path: "/"})
	return req
}

func decodeSessionCookie(t *testing.T, rr *httptest.ResponseRecorder) domain.UserSession {
	t.Helper()

	res := rr.Result()
	defer res.Body.Close()

	sc := securecookie.New([]byte(testHashKey), nil)
	for _, cookie := range res.Cookies() {
		if cookie.Name != "clph_session" {
			continue
		}
		var session domain.UserSession
		if err := sc.Decode("clph_session", cookie.Value, &session); err != nil {
			t.Fatalf("decode session: %v", err)
		}
		return session
	}
	t.Fatal("expected clph_session cookie")
	return domain.UserSession{}
}

func TestDevModePanelVisibility(t *testing.T) {
	session := domain.UserSession{
		GitHubUser: domain.User{
			GitHubUsername: "admin",
			DisplayName:    "Admin User",
		},
		UserID:          1,
		RoleID:          1,
		RoleSlug:        users.RoleSlugAdministrator,
		LastVisitedPath: "/dashboard",
		Active:          true,
	}

	t.Run("visible when enabled", func(t *testing.T) {
		h, _, _, _ := newDevModeHandler(t, true)
		req := newSessionRequest(t, http.MethodGet, "/dashboard", session, "")
		rr := httptest.NewRecorder()
		h.Router([]byte("12345678901234567890123456789012")).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "Developer Tools") {
			t.Fatalf("expected developer tools panel, body=%s", body)
		}
		if !strings.Contains(body, `/dev/impersonate-role`) {
			t.Fatalf("expected impersonation form action, body=%s", body)
		}
	})

	t.Run("hidden when disabled", func(t *testing.T) {
		h, _, _, _ := newDevModeHandler(t, false)
		req := newSessionRequest(t, http.MethodGet, "/dashboard", session, "")
		rr := httptest.NewRecorder()
		h.Router([]byte("12345678901234567890123456789012")).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		body := rr.Body.String()
		if strings.Contains(body, "Developer Tools") {
			t.Fatalf("did not expect developer tools panel, body=%s", body)
		}
		if strings.Contains(body, `/dev/impersonate-role`) {
			t.Fatalf("did not expect impersonation form action, body=%s", body)
		}
	})
}

func TestDevModeImpersonationChangesSessionNotDatabaseAndAudits(t *testing.T) {
	h, oauth, userRepo, auditRepo := newDevModeHandler(t, true)
	session := domain.UserSession{
		GitHubUser: domain.User{
			GitHubUsername: "admin",
			DisplayName:    "Admin User",
		},
		UserID:          1,
		RoleID:          1,
		RoleSlug:        users.RoleSlugAdministrator,
		LastVisitedPath: "/admin/users",
		Active:          true,
	}

	form := url.Values{"role": {users.RoleSlugReader}}
	req := newSessionRequest(t, http.MethodPost, "/dev/impersonate-role", session, form.Encode())
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	oauth.AuthMiddleware(http.HandlerFunc(h.impersonateRole)).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	if location := rr.Header().Get("Location"); location != "/admin/users" {
		t.Fatalf("expected redirect to /admin/users, got %q", location)
	}

	updated := decodeSessionCookie(t, rr)
	if updated.EffectiveRoleSlug() != users.RoleSlugReader {
		t.Fatalf("expected effective role reader, got %q", updated.EffectiveRoleSlug())
	}
	if updated.RoleSlug != users.RoleSlugAdministrator {
		t.Fatalf("expected stored role administrator, got %q", updated.RoleSlug)
	}
	if !updated.IsImpersonating() {
		t.Fatal("expected impersonation to be active")
	}

	stored, err := userRepo.GetByID(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if stored.RoleID != 1 {
		t.Fatalf("expected database role to remain 1, got %d", stored.RoleID)
	}

	if len(auditRepo.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(auditRepo.entries))
	}
	if auditRepo.entries[0].Action != audit.ActionRoleImpersonation {
		t.Fatalf("expected audit action %q, got %q", audit.ActionRoleImpersonation, auditRepo.entries[0].Action)
	}
}

func TestDevModeImpersonationAffectsPermissions(t *testing.T) {
	h, oauth, _, _ := newDevModeHandler(t, true)
	router := h.Router([]byte("12345678901234567890123456789012"))
	session := domain.UserSession{
		GitHubUser: domain.User{
			GitHubUsername: "admin",
			DisplayName:    "Admin User",
		},
		UserID:          1,
		RoleID:          1,
		RoleSlug:        users.RoleSlugAdministrator,
		LastVisitedPath: "/admin/users",
		Active:          true,
	}

	form := url.Values{"role": {users.RoleSlugReader}}
	switchReq := newSessionRequest(t, http.MethodPost, "/dev/impersonate-role", session, form.Encode())
	switchRR := httptest.NewRecorder()
	oauth.AuthMiddleware(http.HandlerFunc(h.impersonateRole)).ServeHTTP(switchRR, switchReq)
	updated := decodeSessionCookie(t, switchRR)

	adminReq := newSessionRequest(t, http.MethodGet, "/admin/users", updated, "")
	adminRR := httptest.NewRecorder()
	router.ServeHTTP(adminRR, adminReq)
	if adminRR.Code != http.StatusForbidden {
		t.Fatalf("expected admin route to be forbidden, got %d", adminRR.Code)
	}

	inventoryReq := newSessionRequest(t, http.MethodGet, "/oci/discover", updated, "")
	inventoryRR := httptest.NewRecorder()
	router.ServeHTTP(inventoryRR, inventoryReq)
	if inventoryRR.Code != http.StatusOK {
		t.Fatalf("expected reader inventory access, got %d", inventoryRR.Code)
	}
}

func TestDevModeImpersonationDisabledWhenOff(t *testing.T) {
	h, oauth, _, _ := newDevModeHandler(t, false)
	session := domain.UserSession{
		GitHubUser: domain.User{
			GitHubUsername: "admin",
			DisplayName:    "Admin User",
		},
		UserID:          1,
		RoleID:          1,
		RoleSlug:        users.RoleSlugAdministrator,
		LastVisitedPath: "/wizard",
		Active:          true,
	}

	form := url.Values{"role": {users.RoleSlugReader}}
	req := newSessionRequest(t, http.MethodPost, "/dev/impersonate-role", session, form.Encode())
	rr := httptest.NewRecorder()
	oauth.AuthMiddleware(http.HandlerFunc(h.impersonateRole)).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestDevModeUserImpersonationChangesSessionNotDatabaseAndAudits(t *testing.T) {
	h, oauth, userRepo, auditRepo := newDevModeHandler(t, true)
	session := domain.UserSession{
		GitHubUser: domain.User{
			GitHubUsername: "admin",
			DisplayName:    "Admin User",
		},
		UserID:          1,
		RoleID:          1,
		RoleSlug:        users.RoleSlugAdministrator,
		LastVisitedPath: "/dashboard",
		Active:          true,
	}

	form := url.Values{"user_id": {"2"}}
	req := newSessionRequest(t, http.MethodPost, "/dev/impersonate-user", session, form.Encode())
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	oauth.AuthMiddleware(http.HandlerFunc(h.impersonateUser)).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}

	updated := decodeSessionCookie(t, rr)

	// GitHub identity is preserved.
	if updated.GitHubUser.GitHubUsername != "admin" {
		t.Fatalf("expected GitHub username to remain 'admin', got %q", updated.GitHubUser.GitHubUsername)
	}
	if updated.UserID != 1 {
		t.Fatalf("expected real UserID to remain 1, got %d", updated.UserID)
	}

	// Impersonated user fields are set.
	if updated.ImpersonatedUserID != 2 {
		t.Fatalf("expected ImpersonatedUserID 2, got %d", updated.ImpersonatedUserID)
	}
	if updated.EffectiveUserID() != 2 {
		t.Fatalf("expected EffectiveUserID 2, got %d", updated.EffectiveUserID())
	}
	if updated.EffectiveRoleSlug() != users.RoleSlugReader {
		t.Fatalf("expected effective role reader, got %q", updated.EffectiveRoleSlug())
	}
	if !updated.IsImpersonating() {
		t.Fatal("expected impersonation to be active")
	}

	// Real role is unchanged.
	if updated.RoleSlug != users.RoleSlugAdministrator {
		t.Fatalf("expected stored role to remain administrator, got %q", updated.RoleSlug)
	}

	// Database is unchanged.
	stored, err := userRepo.GetByID(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if stored.RoleID != 1 {
		t.Fatalf("expected database role to remain 1, got %d", stored.RoleID)
	}

	// Audit entry recorded.
	if len(auditRepo.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(auditRepo.entries))
	}
	if auditRepo.entries[0].Action != audit.ActionUserImpersonation {
		t.Fatalf("expected audit action %q, got %q", audit.ActionUserImpersonation, auditRepo.entries[0].Action)
	}
}

func TestDevModeUserImpersonationClear(t *testing.T) {
	h, oauth, _, _ := newDevModeHandler(t, true)
	session := domain.UserSession{
		GitHubUser: domain.User{
			GitHubUsername: "admin",
			DisplayName:    "Admin User",
		},
		UserID:               1,
		RoleID:               1,
		RoleSlug:             users.RoleSlugAdministrator,
		ImpersonatedUserID:   2,
		ImpersonatedRoleSlug: users.RoleSlugReader,
		ImpersonatedTeamName: "Platform",
		LastVisitedPath:      "/dashboard",
		Active:               true,
	}

	form := url.Values{"user_id": {"0"}}
	req := newSessionRequest(t, http.MethodPost, "/dev/impersonate-user", session, form.Encode())
	rr := httptest.NewRecorder()
	oauth.AuthMiddleware(http.HandlerFunc(h.impersonateUser)).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}

	updated := decodeSessionCookie(t, rr)
	if updated.ImpersonatedUserID != 0 {
		t.Fatalf("expected ImpersonatedUserID 0 after clear, got %d", updated.ImpersonatedUserID)
	}
	if updated.ImpersonatedRoleSlug != "" {
		t.Fatalf("expected ImpersonatedRoleSlug empty after clear, got %q", updated.ImpersonatedRoleSlug)
	}
	if updated.IsImpersonating() {
		t.Fatal("expected impersonation to be inactive after clear")
	}
	if updated.EffectiveUserID() != 1 {
		t.Fatalf("expected EffectiveUserID to be real UserID 1 after clear, got %d", updated.EffectiveUserID())
	}
}

func TestDevModeUserImpersonationAffectsPermissions(t *testing.T) {
	h, oauth, _, _ := newDevModeHandler(t, true)
	router := h.Router([]byte("12345678901234567890123456789012"))
	session := domain.UserSession{
		GitHubUser: domain.User{
			GitHubUsername: "admin",
			DisplayName:    "Admin User",
		},
		UserID:          1,
		RoleID:          1,
		RoleSlug:        users.RoleSlugAdministrator,
		LastVisitedPath: "/admin/users",
		Active:          true,
	}

	// Impersonate the reader user.
	form := url.Values{"user_id": {"2"}}
	switchReq := newSessionRequest(t, http.MethodPost, "/dev/impersonate-user", session, form.Encode())
	switchRR := httptest.NewRecorder()
	oauth.AuthMiddleware(http.HandlerFunc(h.impersonateUser)).ServeHTTP(switchRR, switchReq)
	updated := decodeSessionCookie(t, switchRR)

	// Admin route is now forbidden.
	adminReq := newSessionRequest(t, http.MethodGet, "/admin/users", updated, "")
	adminRR := httptest.NewRecorder()
	router.ServeHTTP(adminRR, adminReq)
	if adminRR.Code != http.StatusForbidden {
		t.Fatalf("expected admin route to be forbidden, got %d", adminRR.Code)
	}

	// Dashboard is accessible.
	dashReq := newSessionRequest(t, http.MethodGet, "/dashboard", updated, "")
	dashRR := httptest.NewRecorder()
	router.ServeHTTP(dashRR, dashReq)
	if dashRR.Code != http.StatusOK {
		t.Fatalf("expected dashboard to be accessible, got %d", dashRR.Code)
	}
}

func TestDevModeUserImpersonationDisabledWhenOff(t *testing.T) {
	h, oauth, _, _ := newDevModeHandler(t, false)
	session := domain.UserSession{
		GitHubUser: domain.User{
			GitHubUsername: "admin",
			DisplayName:    "Admin User",
		},
		UserID:          1,
		RoleID:          1,
		RoleSlug:        users.RoleSlugAdministrator,
		LastVisitedPath: "/dashboard",
		Active:          true,
	}

	form := url.Values{"user_id": {"2"}}
	req := newSessionRequest(t, http.MethodPost, "/dev/impersonate-user", session, form.Encode())
	rr := httptest.NewRecorder()
	oauth.AuthMiddleware(http.HandlerFunc(h.impersonateUser)).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestDevModeImpersonationDisabledForDevelopmentLoginSessions(t *testing.T) {
	h, oauth, _, _ := newDevModeHandler(t, true)
	session := domain.UserSession{
		GitHubUser: domain.User{
			GitHubUsername: "sam.holden",
			DisplayName:    "Sam Holden",
		},
		UserID:     1,
		RoleID:     1,
		RoleSlug:   users.RoleSlugAdministrator,
		AuthSource: "dev",
		Active:     true,
	}

	roleForm := url.Values{"role": {users.RoleSlugReader}}
	roleReq := newSessionRequest(t, http.MethodPost, "/dev/impersonate-role", session, roleForm.Encode())
	roleRR := httptest.NewRecorder()
	oauth.AuthMiddleware(http.HandlerFunc(h.impersonateRole)).ServeHTTP(roleRR, roleReq)
	if roleRR.Code != http.StatusNotFound {
		t.Fatalf("expected role impersonation 404 for dev login session, got %d", roleRR.Code)
	}

	userForm := url.Values{"user_id": {"2"}}
	userReq := newSessionRequest(t, http.MethodPost, "/dev/impersonate-user", session, userForm.Encode())
	userRR := httptest.NewRecorder()
	oauth.AuthMiddleware(http.HandlerFunc(h.impersonateUser)).ServeHTTP(userRR, userReq)
	if userRR.Code != http.StatusNotFound {
		t.Fatalf("expected user impersonation 404 for dev login session, got %d", userRR.Code)
	}
}
