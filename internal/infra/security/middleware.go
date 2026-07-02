// Package security provides GitHub OAuth authentication and security middleware.
package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/h3ow3d/special-dollop/internal/domain"
)

type ctxKey string

const (
	userKey    ctxKey = "currentUser"
	sessionKey ctxKey = "userSession"
)

// UserFromContext retrieves the GitHub user identity from the request context.
// It returns the GitHubUser field of the session, for backward compatibility.
func UserFromContext(ctx context.Context) (domain.User, bool) {
	if s, ok := ctx.Value(sessionKey).(domain.UserSession); ok {
		return s.GitHubUser, true
	}
	// Legacy: plain domain.User stored before UserSession was introduced.
	u, ok := ctx.Value(userKey).(domain.User)
	return u, ok
}

// SessionFromContext retrieves the full UserSession from the request context.
func SessionFromContext(ctx context.Context) (domain.UserSession, bool) {
	s, ok := ctx.Value(sessionKey).(domain.UserSession)
	return s, ok
}

// UserEnricher is an optional hook called after successful GitHub OAuth. It
// receives the raw GitHub identity and returns a fully populated UserSession
// (including RBAC state). If nil, a minimal session containing only the GitHub
// identity is created.
type UserEnricher interface {
	Enrich(ctx context.Context, user domain.User, githubUserID int64, ip string) (domain.UserSession, error)
}

// GitHubOAuthConfig holds GitHub OAuth2 application credentials and runtime options.
type GitHubOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// SecureCookies should be true in production (HTTPS). Set to false for local HTTP development.
	SecureCookies bool
}

// OAuthHandler implements the GitHub OAuth2 flow.
type OAuthHandler struct {
	cfg      GitHubOAuthConfig
	sc       *securecookie.SecureCookie
	enricher UserEnricher // optional; nil → no DB enrichment
}

// NewOAuthHandler creates an OAuthHandler.
// hashKey must be at least 32 bytes; it is used to sign the session and state cookies.
func NewOAuthHandler(cfg GitHubOAuthConfig, hashKey []byte) *OAuthHandler {
	return &OAuthHandler{cfg: cfg, sc: securecookie.New(hashKey, nil)}
}

// WithEnricher attaches a UserEnricher to the handler and returns it for fluent
// chaining.
func (h *OAuthHandler) WithEnricher(e UserEnricher) *OAuthHandler {
	h.enricher = e
	return h
}

// SecureCookies reports whether cookies should be sent with the Secure flag.
func (h *OAuthHandler) SecureCookies() bool { return h.cfg.SecureCookies }

// SetSessionCookie signs and stores the current session in the session cookie.
func (h *OAuthHandler) SetSessionCookie(w http.ResponseWriter, session domain.UserSession) error {
	encoded, err := h.sc.Encode("clph_session", session)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "clph_session",
		Value:    encoded,
		HttpOnly: true,
		Secure:   h.cfg.SecureCookies,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   86400, // 24 hours
	})
	return nil
}

// RedirectToGitHub handles GET /auth/login.
// It generates a random state, stores it in a temporary cookie, and redirects
// the user to GitHub's authorisation endpoint.
func (h *OAuthHandler) RedirectToGitHub(w http.ResponseWriter, r *http.Request) {
state, err := randomState()
if err != nil {
http.Error(w, "internal error", http.StatusInternalServerError)
return
}
encoded, err := h.sc.Encode("oauth_state", state)
if err != nil {
http.Error(w, "internal error", http.StatusInternalServerError)
return
}
http.SetCookie(w, &http.Cookie{
Name:     "clph_oauth_state",
Value:    encoded,
HttpOnly: true,
Secure:   h.cfg.SecureCookies,
SameSite: http.SameSiteLaxMode,
Path:     "/auth/callback",
MaxAge:   300,
})

authURL := fmt.Sprintf(
"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=user%%3Aemail%%20read%%3Aorg%%20write%%3Apackages&state=%s",
url.QueryEscape(h.cfg.ClientID),
url.QueryEscape(h.cfg.RedirectURL),
url.QueryEscape(state),
)
http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback handles GET /auth/callback.
// It verifies the state, exchanges the code for a token, fetches the GitHub user,
// sets a signed session cookie, and redirects to the wizard.
func (h *OAuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state
	stateCookie, err := r.Cookie("clph_oauth_state")
	if err != nil {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		return
	}
	var expectedState string
	if err := h.sc.Decode("oauth_state", stateCookie.Value, &expectedState); err != nil {
		http.Error(w, "invalid state cookie", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != expectedState {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "clph_oauth_state",
		Value:    "",
		HttpOnly: true,
		Secure:   h.cfg.SecureCookies,
		Path:     "/auth/callback",
		MaxAge:   -1,
	})

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	token, err := h.exchangeCode(r.Context(), code)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	gitHubUser, githubUserID, err := h.fetchUser(r.Context(), token)
	if err != nil {
		http.Error(w, "fetch user failed", http.StatusInternalServerError)
		return
	}
	gitHubUser.GitHubToken = token

	var session domain.UserSession
	if h.enricher != nil {
		ip := r.RemoteAddr
		session, err = h.enricher.Enrich(r.Context(), gitHubUser, githubUserID, ip)
		if err != nil {
			http.Error(w, "authentication failed: "+err.Error(), http.StatusForbidden)
			return
		}
	} else {
		session = domain.UserSession{
			GitHubUser: gitHubUser,
			LoginAt:    time.Now().UTC(),
			Active:     true,
		}
	}

	if err := h.SetSessionCookie(w, session); err != nil {
		http.Error(w, "session encode failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/wizard", http.StatusFound)
}

// exchangeCode exchanges an OAuth2 code for a GitHub access token.
func (h *OAuthHandler) exchangeCode(ctx context.Context, code string) (string, error) {
resp, err := http.PostForm("https://github.com/login/oauth/access_token", url.Values{
"client_id":     {h.cfg.ClientID},
"client_secret": {h.cfg.ClientSecret},
"code":          {code},
"redirect_uri":  {h.cfg.RedirectURL},
})
if err != nil {
return "", fmt.Errorf("token request: %w", err)
}
defer resp.Body.Close()

body, err := io.ReadAll(resp.Body)
if err != nil {
return "", fmt.Errorf("read token response: %w", err)
}
vals, err := url.ParseQuery(string(body))
if err != nil {
return "", fmt.Errorf("parse token response: %w", err)
}
token := vals.Get("access_token")
if token == "" {
return "", fmt.Errorf("no access_token in response: %s", string(body))
}
return token, nil
}

// githubUser is the GitHub user API response (subset).
type githubUser struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
	ID    int64  `json:"id"`
	// AvatarURL is the GitHub-provided avatar image URL.
	AvatarURL string `json:"avatar_url"`
}

// githubEmail is one entry from GET /user/emails.
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// githubOrg is one entry from GET /user/orgs.
type githubOrg struct {
	Login string `json:"login"`
}

// githubTeam is one entry from GET /user/teams.
type githubTeam struct {
	Slug string `json:"slug"`
}

// fetchUser retrieves GitHub user identity using the provided access token.
// It returns the domain.User, the raw GitHub numeric user ID, and any error.
func (h *OAuthHandler) fetchUser(ctx context.Context, token string) (domain.User, int64, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return domain.User{}, 0, fmt.Errorf("github user api: %w", err)
	}
	defer resp.Body.Close()

	var gu githubUser
	if err := json.NewDecoder(resp.Body).Decode(&gu); err != nil {
		return domain.User{}, 0, fmt.Errorf("decode user: %w", err)
	}

	email := gu.Email
	if email == "" {
		email = h.fetchPrimaryEmail(ctx, token)
	}

	displayName := gu.Name
	if displayName == "" {
		displayName = gu.Login
	}

	org := h.fetchPrimaryOrg(ctx, token)
	teams := h.fetchTeamSlugs(ctx, token)

	return domain.User{
		GitHubUsername: gu.Login,
		DisplayName:    displayName,
		Email:          email,
		AvatarURL:      gu.AvatarURL,
		Organisation:   org,
		TeamMembership: teams,
		OIDCSubject:    fmt.Sprintf("github:%s", gu.Login),
	}, gu.ID, nil
}

// fetchPrimaryEmail retrieves the user's primary verified email from GitHub.
func (h *OAuthHandler) fetchPrimaryEmail(ctx context.Context, token string) string {
req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
req.Header.Set("Authorization", "Bearer "+token)
req.Header.Set("Accept", "application/vnd.github.v3+json")

resp, err := http.DefaultClient.Do(req)
if err != nil {
return ""
}
defer resp.Body.Close()

var emails []githubEmail
if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
return ""
}
for _, e := range emails {
if e.Primary && e.Verified {
return e.Email
}
}
return ""
}

// fetchPrimaryOrg returns the login of the first organisation the user belongs to.
// Returns an empty string if the user belongs to no organisations or the call fails.
func (h *OAuthHandler) fetchPrimaryOrg(ctx context.Context, token string) string {
req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/orgs?per_page=1", nil)
req.Header.Set("Authorization", "Bearer "+token)
req.Header.Set("Accept", "application/vnd.github.v3+json")

resp, err := http.DefaultClient.Do(req)
if err != nil {
return ""
}
defer resp.Body.Close()

var orgs []githubOrg
if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil || len(orgs) == 0 {
return ""
}
return orgs[0].Login
}

// fetchTeamSlugs returns the slug of every team the user belongs to (up to 100).
// Returns nil if the call fails or the user belongs to no teams.
func (h *OAuthHandler) fetchTeamSlugs(ctx context.Context, token string) []string {
req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/teams?per_page=100", nil)
req.Header.Set("Authorization", "Bearer "+token)
req.Header.Set("Accept", "application/vnd.github.v3+json")

resp, err := http.DefaultClient.Do(req)
if err != nil {
return nil
}
defer resp.Body.Close()

var teams []githubTeam
if err := json.NewDecoder(resp.Body).Decode(&teams); err != nil || len(teams) == 0 {
return nil
}
slugs := make([]string, 0, len(teams))
for _, t := range teams {
slugs = append(slugs, t.Slug)
}
return slugs
}

// AuthMiddleware reads the signed session cookie and populates the request context
// with the authenticated user session. Requests without a valid session continue
// without a user; protected routes should use RequireAuth.
func (h *OAuthHandler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("clph_session")
		if err == nil && cookie.Value != "" {
			var session domain.UserSession
			if err := h.sc.Decode("clph_session", cookie.Value, &session); err == nil {
				ctx := context.WithValue(r.Context(), sessionKey, session)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAuth is middleware that rejects unauthenticated requests with a redirect
// to the login page.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := UserFromContext(r.Context())
		if !ok {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders adds standard security response headers.
func SecurityHeaders(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Security-Policy",
"default-src 'self'; script-src 'self' https://unpkg.com https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'")
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("X-Frame-Options", "DENY")
next.ServeHTTP(w, r)
})
}

// randomState generates a cryptographically random OAuth2 state value.
func randomState() (string, error) {
b := make([]byte, 16)
if _, err := rand.Read(b); err != nil {
return "", err
}
return hex.EncodeToString(b), nil
}
