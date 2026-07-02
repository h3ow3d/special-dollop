package web

import (
	"context"
	"net/http"

	"github.com/h3ow3d/special-dollop/internal/bootstrap"
	"github.com/h3ow3d/special-dollop/internal/domain"
)

// DevLoginProvider abstracts the bootstrap.LoginService for the web layer.
// It is only non-nil when devMode=true.
type DevLoginProvider interface {
	// Users returns the list of development bootstrap users.
	Users() []bootstrap.DevUserSpec
	// CreateSession builds a fully authenticated session for the named dev user.
	CreateSession(ctx context.Context, username, ip string) (domain.UserSession, error)
}

// devLogin handles GET /dev/login (standalone dev login page). In practice the
// dev login form lives on the home page (GET /), so this redirects there.
func (h *Handler) devLogin(w http.ResponseWriter, r *http.Request) {
	if !h.devMode {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// devLoginPost handles POST /dev/login. It creates an authenticated session for
// the selected bootstrap user and redirects to the dashboard.
func (h *Handler) devLoginPost(w http.ResponseWriter, r *http.Request) {
	if !h.devMode || h.devLoginSvc == nil {
		http.NotFound(w, r)
		return
	}

	username := r.FormValue("dev_username")
	session, err := h.devLoginSvc.CreateSession(r.Context(), username, r.RemoteAddr)
	if err != nil {
		http.Error(w, "development login failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.oauth.SetSessionCookie(w, session); err != nil {
		http.Error(w, "session encode failed", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
