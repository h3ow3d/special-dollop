package web

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"
	"github.com/h3ow3d/special-dollop/internal/app"
	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/domain"
	"github.com/h3ow3d/special-dollop/internal/infra/security"
	"github.com/h3ow3d/special-dollop/internal/inventory"
	"github.com/h3ow3d/special-dollop/internal/rbac"
)

//go:embed templates/*.html
var templateFS embed.FS

// Handler wires HTTP routes to the assessment wizard service.
type Handler struct {
	svc         *app.Service
	oauth       *security.OAuthHandler
	tmpl        *template.Template
	admin       *AdminHandler     // optional; nil when DB is not configured
	inventory   *InventoryHandler // optional; nil when DB is not configured
	devMode     bool
	devLoginSvc DevLoginProvider // optional; non-nil when devMode=true and DB available
}

// NewHandler creates a Handler, parsing all embedded templates.
func NewHandler(svc *app.Service, oauth *security.OAuthHandler) (*Handler, error) {
	tmpl, err := template.New("").Funcs(templateFuncs()).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Handler{svc: svc, oauth: oauth, tmpl: tmpl}, nil
}

// WithAdminHandler attaches the AdminHandler and returns the receiver for
// fluent chaining.
func (h *Handler) WithAdminHandler(admin *AdminHandler) *Handler {
	h.admin = admin
	return h
}

// WithInventoryHandler attaches the InventoryHandler and returns the receiver
// for fluent chaining.
func (h *Handler) WithInventoryHandler(ih *InventoryHandler) *Handler {
	h.inventory = ih
	return h
}

// WithDevelopmentMode enables or disables development-only UI affordances.
func (h *Handler) WithDevelopmentMode(enabled bool) *Handler {
	h.devMode = enabled
	return h
}

// WithDevLoginService attaches the dev login provider used to authenticate
// bootstrap users without GitHub OAuth. Only effective when devMode=true.
func (h *Handler) WithDevLoginService(svc DevLoginProvider) *Handler {
	h.devLoginSvc = svc
	return h
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "Not available"
			}
			return t.UTC().Format("02 Jan 2006 15:04 MST")
		},
		"hasPrefix": strings.HasPrefix,
		"sub":       func(a, b int) int { return a - b },
		"roleLabel": func(slug string) string {
			switch slug {
			case "administrator":
				return "Administrator"
			case "assessor":
				return "Assessor"
			case "reader":
				return "Reader"
			case "":
				return "Unassigned"
			default:
				return slug
			}
		},
		"sectionMeta": func(name domain.SectionName) domain.SectionMeta {
			return domain.SectionMetadata[name]
		},
		"sectionResp": func(state *domain.AssessmentState, name domain.SectionName) domain.SectionResponse {
			return state.Sections[name]
		},
		"stepLabel": func(step int) string {
			labels := []string{
				"Artefact Information",
				"Sensitivity",
				"Privilege",
				"Provenance",
				"Verifiability",
				"Traceability",
				"Operational Impact",
				"Recoverability",
				"Supply Chain Assurance",
				"Outcome and Rationale",
			}
			if step >= 1 && step <= len(labels) {
				return labels[step-1]
			}
			return fmt.Sprintf("Step %d", step)
		},
		"stepSection": func(step int) domain.SectionName {
			if step >= 2 && step <= 9 {
				return domain.AllSections[step-2]
			}
			return ""
		},
	}
}

// Router builds and returns the HTTP router.
func (h *Handler) Router(csrfKey []byte) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(security.SecurityHeaders)
	r.Use(h.oauth.AuthMiddleware)
	if !h.oauth.SecureCookies() {
		r.Use(plaintextHTTPMiddleware)
	}
	r.Use(csrf.Protect(csrfKey, csrf.Secure(h.oauth.SecureCookies()), csrf.CookieName("clph_csrf")))

	// Health probes
	r.Get("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	r.Get("/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	// Public routes
	r.Get("/", h.home)
	r.Get("/auth/login", h.oauth.RedirectToGitHub)
	r.Get("/auth/callback", h.oauth.HandleCallback)
	r.Get("/auth/logout", h.logout)
	r.Post("/auth/logout", h.logout)
	if h.devMode {
		r.Get("/dev/login", h.devLogin)
		r.Post("/dev/login", h.devLoginPost)
	}

	// Protected routes
	r.Group(func(pr chi.Router) {
		pr.Use(security.RequireAuth)
		pr.Use(rbac.RequireRole(rbac.RoleAdministrator, rbac.RoleAssessor, rbac.RoleReader))

		pr.Get("/dashboard", h.dashboard)
		pr.Get("/profile", h.profile)

		// Inventory routes (all authenticated roles can view)
		if h.inventory != nil {
			h.inventory.RegisterRoutes(pr)
		}

		pr.Get("/wizard", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		})

		pr.Get("/wizard/{id}/step/{n}", h.wizardStep)

		pr.Get("/wizard/{id}/participants", h.wizardParticipants)

		pr.Get("/wizard/{id}/review", h.wizardReview)
		pr.Get("/wizard/{id}/attest", h.wizardAttest)

		pr.Get("/wizard/{id}/publish", h.wizardPublish)

		pr.Get("/wizard/{id}/done", h.wizardDone)

		// OCI discovery
		pr.Get("/oci/discover", h.ociDiscover)
		pr.Post("/oci/resolve", h.ociResolve)

		// Downloads
		pr.Get("/wizard/{id}/download/envelope", h.downloadEnvelope)
		pr.Get("/wizard/{id}/download/statement", h.downloadStatement)
		pr.Get("/wizard/{id}/download/report", h.downloadReport)

		pr.Group(func(wr chi.Router) {
			wr.Use(rbac.RequireRole(rbac.RoleAdministrator, rbac.RoleAssessor))
			wr.Get("/assessments", h.assessments)
			wr.Get("/wizard/new", h.wizardStart)
			wr.Post("/wizard/new", h.wizardCreate)
			wr.Post("/wizard/{id}/step/{n}", h.wizardStepSave)
			wr.Post("/wizard/{id}/participants/add", h.wizardAddParticipant)
			wr.Post("/wizard/{id}/participants/remove/{n}", h.wizardRemoveParticipant)
			wr.Post("/wizard/{id}/attest", h.wizardSign)
			wr.Post("/wizard/{id}/publish", h.wizardPublishPost)
		})

		// Admin routes (only registered when a DB-backed AdminHandler is wired up)
		pr.Group(func(ar chi.Router) {
			ar.Use(rbac.RequireRole(rbac.RoleAdministrator))
			if h.admin != nil {
				h.admin.RegisterRoutes(ar)
			}
		})

	})

	return r
}

// ── Public handlers ──────────────────────────────────────────────────────────

func (h *Handler) home(w http.ResponseWriter, r *http.Request) {
	user, ok := security.UserFromContext(r.Context())
	if ok && user.GitHubUsername != "" {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	data := map[string]any{}
	if h.devMode && h.devLoginSvc != nil {
		data["devLoginUsers"] = h.devLoginSvc.Users()
	}
	h.render(w, r, "index.html", data)
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	session, _ := security.SessionFromContext(r.Context())
	isAdmin := session.EffectiveRoleSlug() == string(rbac.RoleAdministrator)
	data["inventoryAdminView"] = isAdmin
	if h.inventory != nil {
		counts, err := h.inventory.inventorySvc.CountByTeam(r.Context())
		if err == nil {
			if isAdmin {
				ts, err := h.inventory.teamSvc.List(r.Context())
				if err == nil {
					type teamCount struct {
						Name  string
						Count int
					}
					rows := make([]teamCount, 0, len(ts))
					total := 0
					for _, t := range ts {
						c := counts[t.ID]
						rows = append(rows, teamCount{Name: t.Name, Count: c})
						total += c
					}
					data["inventoryByTeam"] = rows
					data["inventoryTotal"] = total
					data["teamTotal"] = len(ts)
				}
			} else if session.TeamID != nil {
				myTeamName := session.EffectiveTeamName()
				if myTeamName == "" {
					if t, err := h.inventory.teamSvc.GetByID(r.Context(), *session.TeamID); err == nil {
						myTeamName = t.Name
					}
				}
				type teamCount struct {
					Name  string
					Count int
				}
				data["inventoryByTeam"] = []teamCount{{Name: myTeamName, Count: counts[*session.TeamID]}}
			}
		}
	}
	h.render(w, r, "dashboard.html", data)
}

func (h *Handler) assessments(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "assessments.html", nil)
}

func (h *Handler) profile(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "profile.html", nil)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	// Record logout audit event when the admin handler is wired (DB available).
	if h.admin != nil {
		if session, ok := security.SessionFromContext(r.Context()); ok && session.UserID != 0 {
			id := session.UserID
			action := audit.ActionLogout
			if session.AuthSource == "dev" {
				action = audit.ActionDevLogout
			}
			h.admin.auditSvc.Record(r.Context(), &id, action, nil, r.RemoteAddr)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "clph_session",
		Value:    "",
		HttpOnly: true,
		Secure:   h.oauth.SecureCookies(),
		Path:     "/",
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// ── Wizard handlers ──────────────────────────────────────────────────────────

func (h *Handler) wizardStart(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"csrf": csrf.Token(r),
	}
	// If an inventory item ID is provided, pre-populate artefact information.
	if h.inventory != nil {
		if idStr := r.URL.Query().Get("inventory_item_id"); idStr != "" {
			if id, err := strconv.ParseInt(idStr, 10, 64); err == nil && id > 0 {
				item, err := h.inventory.inventorySvc.GetByID(r.Context(), id)
				if err == nil {
					// Team isolation: non-administrators may not pre-populate from
					// an inventory item that belongs to another team.
					session, _ := security.SessionFromContext(r.Context())
					if session.EffectiveRoleSlug() != string(rbac.RoleAdministrator) {
						if session.TeamID == nil || *session.TeamID != item.TeamID {
							http.Error(w, "forbidden", http.StatusForbidden)
							return
						}
					}
					data["inventoryItemID"] = id
					data["inventoryItemName"] = item.Name
					data["inventoryRegistry"] = item.Registry
					data["inventoryPackageName"] = item.PackageName
					data["inventoryPackageURL"] = item.PackageURL
				}
			}
		}
	}
	h.render(w, r, "wizard_artefact.html", data)
}

func (h *Handler) wizardCreate(w http.ResponseWriter, r *http.Request) {
	user, _ := security.UserFromContext(r.Context())

	// If inventory is wired, require an inventory item ID.
	var inventoryItemID int64
	if h.inventory != nil {
		idStr := r.FormValue("inventory_item_id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil || id <= 0 {
			http.Redirect(w, r, "/inventory", http.StatusFound)
			return
		}
		item, err := h.inventory.inventorySvc.GetByID(r.Context(), id)
		if err != nil {
			if errors.Is(err, inventory.ErrNotFound) {
				http.Error(w, "inventory item not found", http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		// Team isolation: assessors may only create assessments for their own team's inventory.
		// Readers cannot reach this handler because the route group requires Administrator or
		// Assessor role (see RegisterRoutes). Only the Assessor case needs an explicit team
		// check; Administrators are unrestricted.
		session, _ := security.SessionFromContext(r.Context())
		if session.EffectiveRoleSlug() == string(rbac.RoleAssessor) {
			if session.TeamID == nil || *session.TeamID != item.TeamID {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		inventoryItemID = id
	}

	artefact := domain.ArtefactInfo{
		Name:      r.FormValue("artefact_name"),
		Type:      r.FormValue("artefact_type"),
		Digest:    r.FormValue("artefact_digest"),
		Reference: r.FormValue("artefact_reference"),
		Registry:  r.FormValue("artefact_registry"),
	}
	reviewDate := parseDate(r.FormValue("review_date"))
	state, err := h.svc.StartAssessment(user, artefact, reviewDate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	state.InventoryItemID = inventoryItemID
	h.svc.UpdateState(state)
	http.Redirect(w, r, fmt.Sprintf("/wizard/%s/step/2", state.ID), http.StatusFound)
}

func (h *Handler) wizardStep(w http.ResponseWriter, r *http.Request) {
	state, step, ok := h.loadStep(w, r)
	if !ok {
		return
	}
	tmplName := "wizard_step.html"
	if step == 10 {
		tmplName = "wizard_outcome.html"
	}
	h.render(w, r, tmplName, map[string]any{
		"state": state,
		"step":  step,
		"csrf":  csrf.Token(r),
	})
}

func (h *Handler) wizardStepSave(w http.ResponseWriter, r *http.Request) {
	state, step, ok := h.loadStep(w, r)
	if !ok {
		return
	}

	if step == 10 {
		// Outcome and rationale
		outcome := domain.Outcome(r.FormValue("outcome"))
		pattern := domain.Pattern(r.FormValue("pattern"))
		if err := h.svc.SetOutcome(state.ID, outcome, r.FormValue("rationale"), r.FormValue("controls"), pattern, r.FormValue("pattern_rationale")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/wizard/%s/participants", state.ID), http.StatusFound)
		return
	}

	// Assessment section (steps 2–9)
	sectionName := domain.AllSections[step-2]
	resp := domain.SectionResponse{
		Notes:           r.FormValue("notes"),
		DiscussionNotes: r.FormValue("discussion_notes"),
		Evidence:        parseEvidence(r.FormValue("evidence")),
	}
	if err := h.svc.UpdateSection(state.ID, sectionName, resp); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/wizard/%s/step/%d", state.ID, step+1), http.StatusFound)
}

func (h *Handler) wizardParticipants(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	state, err := h.svc.GetAssessment(id)
	if err != nil {
		http.Error(w, "assessment not found", http.StatusNotFound)
		return
	}
	h.render(w, r, "wizard_participants.html", map[string]any{
		"state": state,
		"csrf":  csrf.Token(r),
	})
}

func (h *Handler) wizardAddParticipant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p := domain.Participant{
		Name:         r.FormValue("name"),
		Role:         r.FormValue("role"),
		Organisation: r.FormValue("organisation"),
	}
	if err := h.svc.AddParticipant(id, p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/wizard/%s/participants", id), http.StatusFound)
}

func (h *Handler) wizardRemoveParticipant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	n, _ := strconv.Atoi(chi.URLParam(r, "n"))
	if err := h.svc.RemoveParticipant(id, n); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/wizard/%s/participants", id), http.StatusFound)
}

func (h *Handler) wizardReview(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	state, err := h.svc.GetAssessment(id)
	if err != nil {
		http.Error(w, "assessment not found", http.StatusNotFound)
		return
	}
	h.render(w, r, "wizard_review.html", map[string]any{
		"state":    state,
		"sections": domain.AllSections,
		"csrf":     csrf.Token(r),
	})
}

func (h *Handler) wizardAttest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	state, err := h.svc.GetAssessment(id)
	if err != nil {
		http.Error(w, "assessment not found", http.StatusNotFound)
		return
	}
	h.render(w, r, "wizard_attest.html", map[string]any{
		"state": state,
		"csrf":  csrf.Token(r),
	})
}

func (h *Handler) wizardSign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.svc.GenerateAndSign(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/wizard/%s/publish", id), http.StatusFound)
}

func (h *Handler) wizardPublish(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	state, err := h.svc.GetAssessment(id)
	if err != nil {
		http.Error(w, "assessment not found", http.StatusNotFound)
		return
	}
	h.render(w, r, "wizard_publish.html", map[string]any{
		"state": state,
		"csrf":  csrf.Token(r),
	})
}

func (h *Handler) wizardPublishPost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	registry := r.FormValue("registry")
	ref := r.FormValue("artifact_ref")
	if _, err := h.svc.PublishAttestation(r.Context(), id, registry, ref); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/wizard/%s/done", id), http.StatusFound)
}

func (h *Handler) wizardDone(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	state, err := h.svc.GetAssessment(id)
	if err != nil {
		http.Error(w, "assessment not found", http.StatusNotFound)
		return
	}
	h.render(w, r, "wizard_done.html", map[string]any{
		"state": state,
	})
}

// ── OCI discovery ─────────────────────────────────────────────────────────────

func (h *Handler) ociDiscover(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "oci_discover.html", map[string]any{
		"csrf": csrf.Token(r),
	})
}

func (h *Handler) ociResolve(w http.ResponseWriter, r *http.Request) {
	// In production, call the OCI Distribution Registry API to resolve the digest.
	// For now, return a simple acknowledgement so the wizard can proceed.
	registry := r.FormValue("registry")
	repo := r.FormValue("repository")
	tag := r.FormValue("tag")
	if registry == "" || repo == "" {
		http.Error(w, "registry and repository are required", http.StatusBadRequest)
		return
	}
	ref := fmt.Sprintf("%s/%s", registry, repo)
	if tag != "" {
		ref += ":" + tag
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"registry":  registry,
		"reference": ref,
		"note":      "Enter the digest manually or use cosign/crane to resolve it before starting the assessment.",
	})
}

// ── Downloads ─────────────────────────────────────────────────────────────────

func (h *Handler) downloadEnvelope(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	state, err := h.svc.GetAssessment(id)
	if err != nil || state.Attestation == nil {
		http.Error(w, "attestation not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="clph-attestation-%s.dsse.json"`, id[:8]))
	_, _ = w.Write(state.Attestation.EnvelopeJSON)
}

func (h *Handler) downloadStatement(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	state, err := h.svc.GetAssessment(id)
	if err != nil || state.Attestation == nil {
		http.Error(w, "attestation not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="clph-statement-%s.json"`, id[:8]))
	_, _ = w.Write(state.Attestation.StatementJSON)
}

func (h *Handler) downloadReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	state, err := h.svc.GetAssessment(id)
	if err != nil {
		http.Error(w, "assessment not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="clph-report-%s.html"`, id[:8]))
	h.render(w, r, "report.html", map[string]any{
		"state":    state,
		"sections": domain.AllSections,
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	if _, ok := data["csrf"]; !ok {
		data["csrf"] = csrf.Token(r)
	}
	user, ok := security.UserFromContext(r.Context())
	if ok {
		data["user"] = user
	}
	session, hasSession := security.SessionFromContext(r.Context())
	if hasSession {
		if r.Method == http.MethodGet {
			if lastVisitedPath := sanitizeReturnTarget(r.URL.RequestURI()); lastVisitedPath != "" && lastVisitedPath != session.LastVisitedPath {
				session.LastVisitedPath = lastVisitedPath
				_ = h.oauth.SetSessionCookie(w, session)
			}
		}
		data["session"] = session
	}
	data["authenticated"] = hasSession
	data["showDevPanel"] = h.devMode
	data["requestURI"] = r.URL.RequestURI()
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) loadStep(w http.ResponseWriter, r *http.Request) (*domain.AssessmentState, int, bool) {
	id := chi.URLParam(r, "id")
	n, err := strconv.Atoi(chi.URLParam(r, "n"))
	if err != nil || n < 2 || n > 10 {
		http.Error(w, "invalid step", http.StatusBadRequest)
		return nil, 0, false
	}
	state, svcErr := h.svc.GetAssessment(id)
	if svcErr != nil {
		http.Error(w, "assessment not found", http.StatusNotFound)
		return nil, 0, false
	}
	return state, n, true
}

func parseDate(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	t, _ := time.Parse("2006-01-02", v)
	return t
}

// parseEvidence splits a textarea value (one reference per line) into EvidenceRef slice.
func parseEvidence(raw string) []domain.EvidenceRef {
	var refs []domain.EvidenceRef
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			refs = append(refs, domain.EvidenceRef{Reference: line, Reviewed: false})
		}
	}
	return refs
}

// plaintextHTTPMiddleware signals to the gorilla/csrf middleware that requests
// are served over plaintext HTTP, so origin checks use the "http" scheme.
func plaintextHTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, csrf.PlaintextHTTPRequest(r))
	})
}
