package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/domain"
	"github.com/h3ow3d/special-dollop/internal/infra/security"
	"github.com/h3ow3d/special-dollop/internal/inventory"
	"github.com/h3ow3d/special-dollop/internal/rbac"
	"github.com/h3ow3d/special-dollop/internal/teams"
)

// InventoryHandler handles inventory list, detail, and management pages.
type InventoryHandler struct {
	inventorySvc *inventory.Service
	teamSvc      *teams.Service
	auditSvc     *audit.Service
	tmpl         *templateRenderer
}

// NewInventoryHandler creates an InventoryHandler.
func NewInventoryHandler(h *Handler, inventorySvc *inventory.Service, teamSvc *teams.Service, auditSvc *audit.Service) *InventoryHandler {
	return &InventoryHandler{
		inventorySvc: inventorySvc,
		teamSvc:      teamSvc,
		auditSvc:     auditSvc,
		tmpl:         &templateRenderer{h: h},
	}
}

// RegisterRoutes adds inventory routes to the provided router. The router must
// already have authentication middleware applied.
func (ih *InventoryHandler) RegisterRoutes(r chi.Router) {
	// All authenticated roles can view inventory.
	r.Get("/inventory", ih.list)
	r.Get("/inventory/{id}", ih.detail)

	// Only administrators and assessors can manage inventory.
	r.Group(func(wr chi.Router) {
		wr.Use(rbac.RequireRole(rbac.RoleAdministrator, rbac.RoleAssessor))
		wr.Get("/inventory/new", ih.newForm)
		wr.Post("/inventory", ih.create)
		wr.Get("/inventory/{id}/edit", ih.editForm)
		wr.Post("/inventory/{id}", ih.update)
		wr.Post("/inventory/{id}/deactivate", ih.deactivate)
		wr.Post("/inventory/{id}/activate", ih.activate)
	})
}

// ── List ──────────────────────────────────────────────────────────────────────

func (ih *InventoryHandler) list(w http.ResponseWriter, r *http.Request) {
	session, _ := security.SessionFromContext(r.Context())
	isAdmin := session.EffectiveRoleSlug() == string(rbac.RoleAdministrator)

	var items []*inventory.InventoryItemWithTeam
	var err error

	// Administrators see all inventory. Assessors and Readers see only their team's items.
	if isAdmin {
		items, err = ih.inventorySvc.List(r.Context())
	} else if session.TeamID != nil {
		items, err = ih.inventorySvc.ListByTeam(r.Context(), *session.TeamID)
	}
	if err != nil {
		http.Error(w, "failed to list inventory: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Apply optional search and filter query params.
	search := strings.ToLower(r.URL.Query().Get("search"))
	filterStatus := r.URL.Query().Get("status")

	var filterTeamID int64
	if isAdmin {
		filterTeamStr := r.URL.Query().Get("team_id")
		if filterTeamStr != "" {
			filterTeamID, _ = strconv.ParseInt(filterTeamStr, 10, 64)
		}
	}

	if search != "" || filterStatus != "" || (isAdmin && filterTeamID != 0) {
		filtered := items[:0]
		for _, item := range items {
			if search != "" && !strings.Contains(strings.ToLower(item.Name), search) &&
				!strings.Contains(strings.ToLower(item.PackageName), search) {
				continue
			}
			if isAdmin && filterTeamID != 0 && item.TeamID != filterTeamID {
				continue
			}
			if filterStatus == "active" && !item.Active {
				continue
			}
			if filterStatus == "inactive" && item.Active {
				continue
			}
			filtered = append(filtered, item)
		}
		items = filtered
	}

	data := map[string]any{
		"items":        items,
		"session":      session,
		"search":       r.URL.Query().Get("search"),
		"filterTeamID": filterTeamID,
		"filterStatus": filterStatus,
		"isAdmin":      isAdmin,
		"teamName":     session.EffectiveTeamName,
		"csrf":         csrf.Token(r),
	}
	if isAdmin {
		ts, err := ih.teamSvc.List(r.Context())
		if err != nil {
			http.Error(w, "failed to list teams: "+err.Error(), http.StatusInternalServerError)
			return
		}
		data["teams"] = ts
	}
	ih.tmpl.render(w, r, "inventory_list.html", data)
}

// ── Detail ────────────────────────────────────────────────────────────────────

func (ih *InventoryHandler) detail(w http.ResponseWriter, r *http.Request) {
	item, ok := ih.loadItem(w, r)
	if !ok {
		return
	}
	session, _ := security.SessionFromContext(r.Context())

	// Team isolation: non-administrators may only view items owned by their team.
	if session.EffectiveRoleSlug() != string(rbac.RoleAdministrator) {
		if session.TeamID == nil || *session.TeamID != item.TeamID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	owningTeam, _ := ih.teamSvc.GetByID(r.Context(), item.TeamID)

	canEdit := false
	if session.EffectiveRoleSlug() == string(rbac.RoleAdministrator) {
		canEdit = true
	} else if session.EffectiveRoleSlug() == string(rbac.RoleAssessor) &&
		session.TeamID != nil && *session.TeamID == item.TeamID {
		canEdit = true
	}

	ih.tmpl.render(w, r, "inventory_detail.html", map[string]any{
		"item":    item,
		"team":    owningTeam,
		"canEdit": canEdit,
		"session": session,
		"csrf":    csrf.Token(r),
	})
}

// ── Create ────────────────────────────────────────────────────────────────────

func (ih *InventoryHandler) newForm(w http.ResponseWriter, r *http.Request) {
	session, _ := security.SessionFromContext(r.Context())
	isAdmin := session.EffectiveRoleSlug() == string(rbac.RoleAdministrator)
	data := map[string]any{
		"session": session,
		"csrf":    csrf.Token(r),
	}
	if isAdmin {
		ts, err := ih.teamSvc.List(r.Context())
		if err != nil {
			http.Error(w, "failed to list teams: "+err.Error(), http.StatusInternalServerError)
			return
		}
		data["teams"] = ts
	}
	ih.tmpl.render(w, r, "inventory_new.html", data)
}

func (ih *InventoryHandler) create(w http.ResponseWriter, r *http.Request) {
	session, _ := security.SessionFromContext(r.Context())

	teamID, err := resolveTeamID(r, session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	item := &inventory.InventoryItem{
		Name:          r.FormValue("name"),
		Description:   r.FormValue("description"),
		TeamID:        teamID,
		Registry:      r.FormValue("registry"),
		PackageURL:    r.FormValue("package_url"),
		PackageName:   r.FormValue("package_name"),
		RepositoryURL: r.FormValue("repository_url"),
	}
	if item.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	if err := ih.inventorySvc.Create(r.Context(), item); err != nil {
		http.Error(w, fmt.Sprintf("create inventory item: %v", err), http.StatusInternalServerError)
		return
	}

	actorID := session.UserID
	ih.auditSvc.Record(r.Context(), &actorID, audit.ActionInventoryCreated,
		map[string]any{"inventory_item_id": item.ID, "name": item.Name, "team_id": teamID}, r.RemoteAddr)

	http.Redirect(w, r, fmt.Sprintf("/inventory/%d", item.ID), http.StatusFound)
}

// ── Edit ──────────────────────────────────────────────────────────────────────

func (ih *InventoryHandler) editForm(w http.ResponseWriter, r *http.Request) {
	item, ok := ih.loadItem(w, r)
	if !ok {
		return
	}
	session, _ := security.SessionFromContext(r.Context())
	if !ih.canModify(session, item.TeamID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ih.tmpl.render(w, r, "inventory_edit.html", map[string]any{
		"item":    item,
		"session": session,
		"csrf":    csrf.Token(r),
	})
}

func (ih *InventoryHandler) update(w http.ResponseWriter, r *http.Request) {
	item, ok := ih.loadItem(w, r)
	if !ok {
		return
	}
	session, _ := security.SessionFromContext(r.Context())
	if !ih.canModify(session, item.TeamID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	item.Name = r.FormValue("name")
	item.Description = r.FormValue("description")
	item.Registry = r.FormValue("registry")
	item.PackageURL = r.FormValue("package_url")
	item.PackageName = r.FormValue("package_name")
	item.RepositoryURL = r.FormValue("repository_url")

	if item.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	if err := ih.inventorySvc.Update(r.Context(), &item.InventoryItem); err != nil {
		http.Error(w, fmt.Sprintf("update inventory item: %v", err), http.StatusInternalServerError)
		return
	}

	actorID := session.UserID
	ih.auditSvc.Record(r.Context(), &actorID, audit.ActionInventoryUpdated,
		map[string]any{"inventory_item_id": item.ID, "name": item.Name}, r.RemoteAddr)

	http.Redirect(w, r, fmt.Sprintf("/inventory/%d", item.ID), http.StatusFound)
}

// ── Activate / Deactivate ─────────────────────────────────────────────────────

func (ih *InventoryHandler) deactivate(w http.ResponseWriter, r *http.Request) {
	ih.setActive(w, r, false)
}

func (ih *InventoryHandler) activate(w http.ResponseWriter, r *http.Request) {
	ih.setActive(w, r, true)
}

func (ih *InventoryHandler) setActive(w http.ResponseWriter, r *http.Request, active bool) {
	item, ok := ih.loadItem(w, r)
	if !ok {
		return
	}
	session, _ := security.SessionFromContext(r.Context())
	if !ih.canModify(session, item.TeamID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := ih.inventorySvc.SetActive(r.Context(), item.ID, active); err != nil {
		http.Error(w, fmt.Sprintf("set active: %v", err), http.StatusInternalServerError)
		return
	}
	action := audit.ActionInventoryDeactivated
	if active {
		action = audit.ActionInventoryActivated
	}
	actorID := session.UserID
	ih.auditSvc.Record(r.Context(), &actorID, action,
		map[string]any{"inventory_item_id": item.ID, "active": active}, r.RemoteAddr)
	http.Redirect(w, r, fmt.Sprintf("/inventory/%d", item.ID), http.StatusFound)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (ih *InventoryHandler) loadItem(w http.ResponseWriter, r *http.Request) (*inventory.InventoryItemWithTeam, bool) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return nil, false
	}
	raw, err := ih.inventorySvc.GetByID(r.Context(), id)
	if err != nil {
		if err == inventory.ErrNotFound {
			http.Error(w, "inventory item not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return nil, false
	}
	// Resolve team name.
	item := &inventory.InventoryItemWithTeam{InventoryItem: *raw}
	if t, err := ih.teamSvc.GetByID(r.Context(), raw.TeamID); err == nil {
		item.TeamName = t.Name
	}
	return item, true
}

// canModify returns true if the session user may modify an inventory item
// owned by the given team. Administrators can modify any item; assessors may
// only modify items belonging to their own team.
func (ih *InventoryHandler) canModify(session domain.UserSession, teamID int64) bool {
	switch session.EffectiveRoleSlug() {
	case string(rbac.RoleAdministrator):
		return true
	case string(rbac.RoleAssessor):
		return session.TeamID != nil && *session.TeamID == teamID
	default:
		return false
	}
}

// resolveTeamID returns the team ID to assign to a new inventory item. For
// administrators the team_id form value is used; for assessors the team from
// their session is used (ignoring any form value to prevent privilege escalation).
func resolveTeamID(r *http.Request, session domain.UserSession) (int64, error) {
	if session.EffectiveRoleSlug() == string(rbac.RoleAdministrator) {
		v := r.FormValue("team_id")
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id <= 0 {
			return 0, fmt.Errorf("team_id is required")
		}
		return id, nil
	}
	// Assessor: use their own team.
	if session.TeamID == nil {
		return 0, fmt.Errorf("you must be assigned to a team to create inventory items")
	}
	return *session.TeamID, nil
}
