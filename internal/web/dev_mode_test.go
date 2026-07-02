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
		if strings.Contains(body, `/dev/impersonate-`) {
			t.Fatalf("did not expect impersonation controls, body=%s", body)
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
	})
}

func TestImpersonationRoutesRemoved(t *testing.T) {
	h, _, _, _ := newDevModeHandler(t, true)
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

	homeReq := newSessionRequest(t, http.MethodGet, "/dashboard", session, "")
	homeRR := httptest.NewRecorder()
	router.ServeHTTP(homeRR, homeReq)
	if homeRR.Code != http.StatusOK {
		t.Fatalf("expected dashboard 200, got %d", homeRR.Code)
	}

	csrfToken := extractCSRFToken(t, homeRR.Body.String())
	csrfCookie := extractCookie(homeRR, "clph_csrf")
	if csrfCookie == nil {
		t.Fatal("expected CSRF cookie")
	}

	tests := []struct {
		name string
		path string
		form url.Values
	}{
		{
			name: "role route",
			path: "/dev/impersonate-role",
			form: url.Values{"role": {users.RoleSlugReader}, "gorilla.csrf.Token": {csrfToken}},
		},
		{
			name: "user route",
			path: "/dev/impersonate-user",
			form: url.Values{"user_id": {"2"}, "gorilla.csrf.Token": {csrfToken}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newSessionRequest(t, http.MethodPost, tc.path, session, tc.form.Encode())
			req.AddCookie(csrfCookie)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusNotFound {
				t.Fatalf("expected 404, got %d", rr.Code)
			}
		})
	}
}
