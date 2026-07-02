package web

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/infra/security"
	"github.com/h3ow3d/special-dollop/internal/teams"
	"github.com/h3ow3d/special-dollop/internal/users"
)

// AdminHandler handles administration pages (users, teams, roles).
type AdminHandler struct {
	userSvc  *users.Service
	teamSvc  *teams.Service
	auditSvc *audit.Service
	tmpl     *templateRenderer
}

// templateRenderer is a thin wrapper so AdminHandler can reuse the same template
// parsing and rendering logic without duplicating it.
type templateRenderer struct {
	h *Handler
}

type adminUserRow struct {
	ID             int64
	GitHubUsername string
	DisplayName    string
	Email          string
	CurrentRole    string
	CurrentTeam    string
	RoleID         int64
	TeamID         int64
	HasTeam        bool
	Active         bool
}

func (tr *templateRenderer) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	tr.h.render(w, r, name, data)
}

// NewAdminHandler creates an AdminHandler.
func NewAdminHandler(h *Handler, userSvc *users.Service, teamSvc *teams.Service, auditSvc *audit.Service) *AdminHandler {
	return &AdminHandler{
		userSvc:  userSvc,
		teamSvc:  teamSvc,
		auditSvc: auditSvc,
		tmpl:     &templateRenderer{h: h},
	}
}

// RegisterRoutes adds admin routes to the provided chi.Router. The router must
// already have authentication and Administrator RBAC middleware applied.
func (ah *AdminHandler) RegisterRoutes(r chi.Router) {
	r.Get("/admin/users", ah.listUsers)
	r.Post("/admin/users/{id}/activate", ah.activateUser)
	r.Post("/admin/users/{id}/deactivate", ah.deactivateUser)
	r.Post("/admin/users/{id}/role", ah.updateUserRole)
	r.Post("/admin/users/{id}/team", ah.updateUserTeam)

	r.Get("/admin/teams", ah.listTeams)
	r.Post("/admin/teams", ah.createTeam)

	r.Get("/admin/roles", ah.listRoles)
}

// ── User administration ───────────────────────────────────────────────────────

func (ah *AdminHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := ah.userSvc.List(r.Context())
	if err != nil {
		http.Error(w, "failed to list users: "+err.Error(), http.StatusInternalServerError)
		return
	}
	roles, err := ah.userSvc.ListRoles(r.Context())
	if err != nil {
		http.Error(w, "failed to list roles: "+err.Error(), http.StatusInternalServerError)
		return
	}
	ts, err := ah.teamSvc.List(r.Context())
	if err != nil {
		http.Error(w, "failed to list teams: "+err.Error(), http.StatusInternalServerError)
		return
	}
	roleNames := make(map[int64]string, len(roles))
	for _, role := range roles {
		roleNames[role.ID] = role.Name
	}
	teamNames := make(map[int64]string, len(ts))
	for _, team := range ts {
		teamNames[team.ID] = team.Name
	}
	rows := make([]adminUserRow, 0, len(us))
	for _, user := range us {
		row := adminUserRow{
			ID:             user.ID,
			GitHubUsername: user.GitHubUsername,
			DisplayName:    user.DisplayName,
			Email:          user.Email,
			CurrentRole:    roleNames[user.RoleID],
			RoleID:         user.RoleID,
			Active:         user.Active,
		}
		if user.TeamID != nil {
			row.HasTeam = true
			row.TeamID = *user.TeamID
			row.CurrentTeam = teamNames[*user.TeamID]
		}
		rows = append(rows, row)
	}
	ah.tmpl.render(w, r, "admin_users.html", map[string]any{
		"users": rows,
		"roles": roles,
		"teams": ts,
		"csrf":  csrf.Token(r),
	})
}

func (ah *AdminHandler) activateUser(w http.ResponseWriter, r *http.Request) {
	id := ah.parseID(w, chi.URLParam(r, "id"))
	if id == 0 {
		return
	}
	if err := ah.userSvc.SetActive(r.Context(), id, true); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, _ := security.SessionFromContext(r.Context())
	actorID := session.UserID
	ah.auditSvc.Record(r.Context(), &actorID, audit.ActionUserActivated,
		map[string]any{"target_user_id": id}, r.RemoteAddr)
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

func (ah *AdminHandler) deactivateUser(w http.ResponseWriter, r *http.Request) {
	id := ah.parseID(w, chi.URLParam(r, "id"))
	if id == 0 {
		return
	}
	if err := ah.userSvc.SetActive(r.Context(), id, false); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, _ := security.SessionFromContext(r.Context())
	actorID := session.UserID
	ah.auditSvc.Record(r.Context(), &actorID, audit.ActionUserDeactivated,
		map[string]any{"target_user_id": id}, r.RemoteAddr)
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

func (ah *AdminHandler) updateUserRole(w http.ResponseWriter, r *http.Request) {
	id := ah.parseID(w, chi.URLParam(r, "id"))
	if id == 0 {
		return
	}
	roleID := ah.parseID(w, r.FormValue("role_id"))
	if roleID == 0 {
		return
	}
	if err := ah.userSvc.AssignRole(r.Context(), id, roleID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, _ := security.SessionFromContext(r.Context())
	actorID := session.UserID
	ah.auditSvc.Record(r.Context(), &actorID, audit.ActionRoleChanged,
		map[string]any{"target_user_id": id, "role_id": roleID}, r.RemoteAddr)
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

func (ah *AdminHandler) updateUserTeam(w http.ResponseWriter, r *http.Request) {
	id := ah.parseID(w, chi.URLParam(r, "id"))
	if id == 0 {
		return
	}
	var teamID *int64
	if v := r.FormValue("team_id"); v != "" && v != "0" {
		tid := ah.parseID(w, v)
		if tid == 0 {
			return
		}
		teamID = &tid
	}
	if err := ah.userSvc.AssignTeam(r.Context(), id, teamID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	session, _ := security.SessionFromContext(r.Context())
	actorID := session.UserID
	ah.auditSvc.Record(r.Context(), &actorID, audit.ActionTeamChanged,
		map[string]any{"target_user_id": id, "team_id": teamID}, r.RemoteAddr)
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

// ── Team administration ───────────────────────────────────────────────────────

func (ah *AdminHandler) listTeams(w http.ResponseWriter, r *http.Request) {
	ts, err := ah.teamSvc.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ah.tmpl.render(w, r, "admin_teams.html", map[string]any{
		"teams": ts,
		"csrf":  csrf.Token(r),
	})
}

func (ah *AdminHandler) createTeam(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	desc := r.FormValue("description")
	if name == "" {
		http.Error(w, "team name is required", http.StatusBadRequest)
		return
	}
	if _, err := ah.teamSvc.Create(r.Context(), name, desc); err != nil {
		http.Error(w, fmt.Sprintf("create team: %v", err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/teams", http.StatusFound)
}

// ── Role listing ──────────────────────────────────────────────────────────────

func (ah *AdminHandler) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := ah.userSvc.ListRoles(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ah.tmpl.render(w, r, "admin_roles.html", map[string]any{
		"roles": roles,
	})
}

func (ah *AdminHandler) parseID(w http.ResponseWriter, s string) int64 {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return 0
	}
	return id
}
