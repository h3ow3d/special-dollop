package web

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/bootstrap"
	"github.com/h3ow3d/special-dollop/internal/domain"
	"github.com/h3ow3d/special-dollop/internal/teams"
	"github.com/h3ow3d/special-dollop/internal/users"
)

// ── fake DevLoginProvider ────────────────────────────────────────────────────

type fakeDevLoginProvider struct {
	devUsers []bootstrap.DevUserSpec
	sessions map[string]domain.UserSession // username → session
	audits   []*audit.Entry
}

func newFakeDevLoginProvider() *fakeDevLoginProvider {
	teamID := int64(10)
	return &fakeDevLoginProvider{
		devUsers: []bootstrap.DevUserSpec{
			{GitHubUserID: -1, Username: "sam.holden", DisplayName: "Sam Holden", Email: "sam.holden@dev.local", RoleSlug: users.RoleSlugAdministrator, TeamName: "Platform Team"},
			{GitHubUserID: -2, Username: "taylor.brown", DisplayName: "Taylor Brown", Email: "taylor.brown@dev.local", RoleSlug: users.RoleSlugAssessor, TeamName: "Applications Team"},
			{GitHubUserID: -3, Username: "morgan.wilson", DisplayName: "Morgan Wilson", Email: "morgan.wilson@dev.local", RoleSlug: users.RoleSlugReader, TeamName: "Applications Team"},
		},
		sessions: map[string]domain.UserSession{
			"sam.holden": {
				GitHubUser:  domain.User{GitHubUsername: "sam.holden", DisplayName: "Sam Holden", Email: "sam.holden@dev.local"},
				UserID:      1,
				RoleID:      1,
				RoleSlug:    users.RoleSlugAdministrator,
				TeamID:      &teamID,
				TeamName:    "Platform Team",
				AuthSource:  bootstrap.AuthSourceDev,
				Active:      true,
			},
			"taylor.brown": {
				GitHubUser:  domain.User{GitHubUsername: "taylor.brown", DisplayName: "Taylor Brown", Email: "taylor.brown@dev.local"},
				UserID:      2,
				RoleID:      2,
				RoleSlug:    users.RoleSlugAssessor,
				TeamID:      &teamID,
				TeamName:    "Applications Team",
				AuthSource:  bootstrap.AuthSourceDev,
				Active:      true,
			},
			"morgan.wilson": {
				GitHubUser:  domain.User{GitHubUsername: "morgan.wilson", DisplayName: "Morgan Wilson", Email: "morgan.wilson@dev.local"},
				UserID:      3,
				RoleID:      3,
				RoleSlug:    users.RoleSlugReader,
				TeamID:      &teamID,
				TeamName:    "Applications Team",
				AuthSource:  bootstrap.AuthSourceDev,
				Active:      true,
			},
		},
	}
}

func (f *fakeDevLoginProvider) Users() []bootstrap.DevUserSpec { return f.devUsers }

func (f *fakeDevLoginProvider) CreateSession(_ context.Context, username, _ string) (domain.UserSession, error) {
	if s, ok := f.sessions[username]; ok {
		return s, nil
	}
	return domain.UserSession{}, &devLoginError{username: username}
}

type devLoginError struct{ username string }

func (e *devLoginError) Error() string { return "unknown dev user: " + e.username }

// ── helpers ──────────────────────────────────────────────────────────────────

func newDevLoginHandler(t *testing.T, enabled bool) (*Handler, *fakeDevLoginProvider) {
	t.Helper()

	h, _ := newTestHandler(t)
	h.WithDevelopmentMode(enabled)

	teamID := int64(10)
	userRepo := &testAdminUserRepo{
		users: []*users.User{
			{ID: 1, GitHubUserID: -1, GitHubUsername: "sam.holden", DisplayName: "Sam Holden", Email: "sam.holden@dev.local", RoleID: 1, TeamID: &teamID, Active: true},
		},
	}
	teamSvc := teams.NewService(&testAdminTeamRepo{teams: []*teams.Team{{ID: 10, Name: "Platform Team", Active: true}}})
	auditSvc := audit.NewService(&testAuditRepo{})
	userSvc := users.NewService(userRepo, &testAdminRoleRepo{})
	h.WithAdminHandler(NewAdminHandler(h, userSvc, teamSvc, auditSvc))

	fakeProv := newFakeDevLoginProvider()
	if enabled {
		h.WithDevLoginService(fakeProv)
	}
	return h, fakeProv
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestDevLoginRouteDisabledWhenDevModeOff(t *testing.T) {
	h, _ := newDevLoginHandler(t, false)

	// Call the handler directly to avoid CSRF middleware running before route
	// matching; when devMode=false the handler must return 404 regardless.
	req := httptest.NewRequest(http.MethodPost, "/dev/login", strings.NewReader("dev_username=sam.holden"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.devLoginPost(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when devMode=false, got %d", rr.Code)
	}
}

func TestDevLoginPostCreatesSession(t *testing.T) {
	h, _ := newDevLoginHandler(t, true)
	router := h.Router([]byte("12345678901234567890123456789012"))

	// First, get a CSRF token from the home page.
	homeReq := httptest.NewRequest(http.MethodGet, "/", nil)
	homeRR := httptest.NewRecorder()
	router.ServeHTTP(homeRR, homeReq)
	if homeRR.Code != http.StatusOK {
		t.Fatalf("home page: expected 200, got %d", homeRR.Code)
	}

	// Extract CSRF token and cookie.
	csrfToken := extractCSRFToken(t, homeRR.Body.String())
	csrfCookie := extractCookie(homeRR, "clph_csrf")
	if csrfCookie == nil {
		t.Fatal("expected CSRF cookie from home page")
	}

	form := url.Values{
		"dev_username":          {"sam.holden"},
		"gorilla.csrf.Token":    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/dev/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d body=%s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/dashboard" {
		t.Fatalf("expected redirect to /dashboard, got %q", loc)
	}

	// Verify session cookie was set with the correct user.
	session := decodeSessionCookie(t, rr)
	if session.GitHubUser.GitHubUsername != "sam.holden" {
		t.Fatalf("expected sam.holden in session, got %q", session.GitHubUser.GitHubUsername)
	}
	if session.RoleSlug != users.RoleSlugAdministrator {
		t.Fatalf("expected administrator role, got %q", session.RoleSlug)
	}
	if session.AuthSource != bootstrap.AuthSourceDev {
		t.Fatalf("expected AuthSource %q, got %q", bootstrap.AuthSourceDev, session.AuthSource)
	}
}

func TestDevLoginPost_InvalidUsername(t *testing.T) {
	h, _ := newDevLoginHandler(t, true)
	router := h.Router([]byte("12345678901234567890123456789012"))

	// Get CSRF token first.
	homeReq := httptest.NewRequest(http.MethodGet, "/", nil)
	homeRR := httptest.NewRecorder()
	router.ServeHTTP(homeRR, homeReq)
	csrfToken := extractCSRFToken(t, homeRR.Body.String())
	csrfCookie := extractCookie(homeRR, "clph_csrf")

	form := url.Values{
		"dev_username":       {"unknown.user"},
		"gorilla.csrf.Token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/dev/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown user, got %d", rr.Code)
	}
}

func TestHomeShowsDevLoginFormWhenEnabled(t *testing.T) {
	h, _ := newDevLoginHandler(t, true)
	router := h.Router([]byte("12345678901234567890123456789012"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Development Login") {
		t.Fatal("expected Development Login section on home page")
	}
	if !strings.Contains(body, "Sam Holden") {
		t.Fatal("expected Sam Holden in dev login dropdown")
	}
	if !strings.Contains(body, "/dev/login") {
		t.Fatal("expected dev login form action")
	}
}

func TestHomeHidesDevLoginFormWhenDisabled(t *testing.T) {
	h, _ := newDevLoginHandler(t, false)
	router := h.Router([]byte("12345678901234567890123456789012"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "Development Login") {
		t.Fatal("did not expect Development Login section when devMode=false")
	}
}

func TestDevLoginExercisesRBAC(t *testing.T) {
	h, _ := newDevLoginHandler(t, true)
	router := h.Router([]byte("12345678901234567890123456789012"))

	// Login as Reader (morgan.wilson) and verify admin routes are forbidden.
	homeReq := httptest.NewRequest(http.MethodGet, "/", nil)
	homeRR := httptest.NewRecorder()
	router.ServeHTTP(homeRR, homeReq)
	csrfToken := extractCSRFToken(t, homeRR.Body.String())
	csrfCookie := extractCookie(homeRR, "clph_csrf")

	form := url.Values{"dev_username": {"morgan.wilson"}, "gorilla.csrf.Token": {csrfToken}}
	loginReq := httptest.NewRequest(http.MethodPost, "/dev/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.AddCookie(csrfCookie)
	loginRR := httptest.NewRecorder()
	router.ServeHTTP(loginRR, loginReq)

	session := decodeSessionCookie(t, loginRR)
	if session.RoleSlug != users.RoleSlugReader {
		t.Fatalf("expected reader role, got %q", session.RoleSlug)
	}

	adminReq := newSessionRequest(t, http.MethodGet, "/admin/users", session, "")
	adminRR := httptest.NewRecorder()
	router.ServeHTTP(adminRR, adminReq)
	if adminRR.Code != http.StatusForbidden {
		t.Fatalf("reader should be forbidden from admin route, got %d", adminRR.Code)
	}
}

func TestDevPanelShowsAuthSourceDev(t *testing.T) {
	h, _ := newDevLoginHandler(t, true)
	router := h.Router([]byte("12345678901234567890123456789012"))

	teamID := int64(10)
	session := domain.UserSession{
		GitHubUser:  domain.User{GitHubUsername: "sam.holden", DisplayName: "Sam Holden"},
		UserID:      1,
		RoleID:      1,
		RoleSlug:    users.RoleSlugAdministrator,
		TeamID:      &teamID,
		TeamName:    "Platform Team",
		AuthSource:  bootstrap.AuthSourceDev,
		Active:      true,
	}

	req := newSessionRequest(t, http.MethodGet, "/dashboard", session, "")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Development Login") {
		t.Fatal("expected Authentication Source: Development Login in dev panel")
	}
	if strings.Contains(rr.Body.String(), "/dev/impersonate-role") {
		t.Fatal("did not expect role impersonation controls for development login sessions")
	}
	if strings.Contains(rr.Body.String(), "/dev/impersonate-user") {
		t.Fatal("did not expect user impersonation controls for development login sessions")
	}
}

func TestDevPanelShowsAuthSourceGitHub(t *testing.T) {
	h, _ := newDevLoginHandler(t, true)
	router := h.Router([]byte("12345678901234567890123456789012"))

	teamID := int64(10)
	session := domain.UserSession{
		GitHubUser:  domain.User{GitHubUsername: "realuser", DisplayName: "Real User"},
		UserID:      99,
		RoleID:      1,
		RoleSlug:    users.RoleSlugAdministrator,
		TeamID:      &teamID,
		TeamName:    "Platform Team",
		AuthSource:  "", // GitHub OAuth user has empty AuthSource
		Active:      true,
	}

	req := newSessionRequest(t, http.MethodGet, "/dashboard", session, "")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "GitHub OAuth") {
		t.Fatal("expected Authentication Source: GitHub OAuth in dev panel")
	}
}

func TestDevLogout_RecordsDevLogoutAudit(t *testing.T) {
	h, _, userRepo, auditRepo := newDevModeHandler(t, true)
	router := h.Router([]byte("12345678901234567890123456789012"))

	teamID := int64(10)
	session := domain.UserSession{
		GitHubUser:  domain.User{GitHubUsername: "sam.holden", DisplayName: "Sam Holden"},
		UserID:      1,
		RoleID:      1,
		RoleSlug:    users.RoleSlugAdministrator,
		TeamID:      &teamID,
		TeamName:    "Platform Team",
		AuthSource:  bootstrap.AuthSourceDev,
		Active:      true,
	}
	// Ensure userRepo knows about user 1.
	teamIDCopy := teamID
	userRepo.users = []*users.User{
		{ID: 1, GitHubUserID: -1, GitHubUsername: "sam.holden", DisplayName: "Sam Holden", RoleID: 1, TeamID: &teamIDCopy, Active: true},
	}

	// Get CSRF token.
	homeReq := newSessionRequest(t, http.MethodGet, "/dashboard", session, "")
	homeRR := httptest.NewRecorder()
	router.ServeHTTP(homeRR, homeReq)
	csrfToken := extractCSRFToken(t, homeRR.Body.String())
	csrfCookie := extractCookie(homeRR, "clph_csrf")

	form := url.Values{"gorilla.csrf.Token": {csrfToken}}
	req := newSessionRequest(t, http.MethodPost, "/auth/logout", session, form.Encode())
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rr.Code)
	}

	if len(auditRepo.entries) == 0 {
		t.Fatal("expected at least one audit entry")
	}
	// Find the dev logout event.
	found := false
	for _, e := range auditRepo.entries {
		if e.Action == audit.ActionDevLogout {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected %q audit action, got entries: %v", audit.ActionDevLogout, auditRepo.entries)
	}
}

func TestDevLogout_RecordsRegularLogoutForGitHubUser(t *testing.T) {
	h, _, userRepo, auditRepo := newDevModeHandler(t, true)
	router := h.Router([]byte("12345678901234567890123456789012"))

	teamID := int64(10)
	session := domain.UserSession{
		GitHubUser:  domain.User{GitHubUsername: "admin", DisplayName: "Admin User"},
		UserID:      1,
		RoleID:      1,
		RoleSlug:    users.RoleSlugAdministrator,
		TeamID:      &teamID,
		TeamName:    "Platform Team",
		AuthSource:  "", // Regular GitHub user
		Active:      true,
	}
	teamIDCopy := teamID
	userRepo.users = []*users.User{
		{ID: 1, GitHubUserID: 101, GitHubUsername: "admin", DisplayName: "Admin User", RoleID: 1, TeamID: &teamIDCopy, Active: true},
	}

	homeReq := newSessionRequest(t, http.MethodGet, "/dashboard", session, "")
	homeRR := httptest.NewRecorder()
	router.ServeHTTP(homeRR, homeReq)
	csrfToken := extractCSRFToken(t, homeRR.Body.String())
	csrfCookie := extractCookie(homeRR, "clph_csrf")

	form := url.Values{"gorilla.csrf.Token": {csrfToken}}
	req := newSessionRequest(t, http.MethodPost, "/auth/logout", session, form.Encode())
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rr.Code)
	}

	found := false
	for _, e := range auditRepo.entries {
		if e.Action == audit.ActionLogout {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected %q audit action for GitHub user logout", audit.ActionLogout)
	}
}

// ── utility helpers ──────────────────────────────────────────────────────────

func extractCSRFToken(t *testing.T, body string) string {
	t.Helper()
	const needle = `name="gorilla.csrf.Token" value="`
	idx := strings.Index(body, needle)
	if idx == -1 {
		t.Fatal("CSRF token not found in response body")
	}
	start := idx + len(needle)
	end := strings.Index(body[start:], `"`)
	if end == -1 {
		t.Fatal("CSRF token not terminated")
	}
	// html/template HTML-escapes values in attributes (e.g. + → &#43;).
	// Unescape so the raw token can be submitted in a form POST.
	return html.UnescapeString(body[start : start+end])
}

func extractCookie(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}
