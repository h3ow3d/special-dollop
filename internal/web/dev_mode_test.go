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
		UserID:   1,
		RoleID:   1,
		RoleSlug: users.RoleSlugAdministrator,
		Active:   true,
	}

	t.Run("visible when enabled", func(t *testing.T) {
		h, _, _, _ := newDevModeHandler(t, true)
		req := newSessionRequest(t, http.MethodGet, "/wizard", session, "")
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
		req := newSessionRequest(t, http.MethodGet, "/wizard", session, "")
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
		UserID:   1,
		RoleID:   1,
		RoleSlug: users.RoleSlugAdministrator,
		Active:   true,
	}

	form := url.Values{"role": {users.RoleSlugReader}, "return_to": {"/admin/users"}}
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
		UserID:   1,
		RoleID:   1,
		RoleSlug: users.RoleSlugAdministrator,
		Active:   true,
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
		UserID:   1,
		RoleID:   1,
		RoleSlug: users.RoleSlugAdministrator,
		Active:   true,
	}

	form := url.Values{"role": {users.RoleSlugReader}}
	req := newSessionRequest(t, http.MethodPost, "/dev/impersonate-role", session, form.Encode())
	rr := httptest.NewRecorder()
	oauth.AuthMiddleware(http.HandlerFunc(h.impersonateRole)).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}
