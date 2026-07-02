package web

import (
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/domain"
	"github.com/h3ow3d/special-dollop/internal/infra/security"
	"github.com/h3ow3d/special-dollop/internal/users"
)

func (h *Handler) impersonateRole(w http.ResponseWriter, r *http.Request) {
	if !h.devMode {
		http.NotFound(w, r)
		return
	}

	session, ok := security.SessionFromContext(r.Context())
	if !ok || session.UserID == 0 {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	role := strings.TrimSpace(r.FormValue("role"))
	if !isSupportedDevRole(role) {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}

	fromRole := session.EffectiveRoleSlug()
	if role == session.RoleSlug {
		session.ImpersonatedRoleSlug = ""
	} else {
		session.ImpersonatedRoleSlug = role
	}

	if err := h.oauth.SetSessionCookie(w, session); err != nil {
		http.Error(w, "session encode failed", http.StatusInternalServerError)
		return
	}

	if h.admin != nil {
		actorID := session.UserID
		h.admin.auditSvc.Record(r.Context(), &actorID, audit.ActionRoleImpersonation, map[string]any{
			"from_role":   fromRole,
			"to_role":     session.EffectiveRoleSlug(),
			"stored_role": session.RoleSlug,
		}, r.RemoteAddr)
	}

	http.Redirect(w, r, devReturnTo(session), http.StatusFound)
}

func isSupportedDevRole(role string) bool {
	switch role {
	case users.RoleSlugAdministrator, users.RoleSlugAssessor, users.RoleSlugReader:
		return true
	default:
		return false
	}
}

func devReturnTo(session domain.UserSession) string {
	if target := sanitizeReturnTarget(session.LastVisitedPath); target != "" {
		return target
	}
	return "/dashboard"
}

func sanitizeReturnTarget(v string) string {
	if v == "" {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" {
		return ""
	}
	rawPath := u.EscapedPath()
	if rawPath == "" {
		rawPath = u.Path
	}
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil || !strings.HasPrefix(decodedPath, "/") || strings.HasPrefix(decodedPath, "//") || strings.Contains(decodedPath, "\\") {
		return ""
	}
	if len(decodedPath) > 1 && (decodedPath[1] == '/' || decodedPath[1] == '\\') {
		return ""
	}
	cleanedPath := path.Clean(decodedPath)
	if cleanedPath == "." || !strings.HasPrefix(cleanedPath, "/") || strings.HasPrefix(cleanedPath, "//") || !hasAllowedDevReturnPrefix(cleanedPath) {
		return ""
	}
	if len(cleanedPath) > 1 && (cleanedPath[1] == '/' || cleanedPath[1] == '\\') {
		return ""
	}
	if u.RawQuery != "" {
		return cleanedPath + "?" + u.RawQuery
	}
	return cleanedPath
}

func hasAllowedDevReturnPrefix(v string) bool {
	switch {
	case strings.HasPrefix(v, "/dashboard"),
		strings.HasPrefix(v, "/wizard"),
		strings.HasPrefix(v, "/admin"),
		strings.HasPrefix(v, "/oci"),
		v == "/":
		return true
	default:
		return false
	}
}
