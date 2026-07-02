package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"
	"github.com/h3ow3d/special-dollop/internal/app"
	"github.com/h3ow3d/special-dollop/internal/domain"
	"github.com/h3ow3d/special-dollop/internal/infra/security"
)

//go:embed templates/*.html
var templateFS embed.FS

type Handler struct {
	svc  *app.Service
	tmpl *template.Template
}

func NewHandler(svc *app.Service) (*Handler, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Handler{svc: svc, tmpl: tmpl}, nil
}

func (h *Handler) Router(csrfKey []byte) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(security.SecurityHeaders)
	r.Use(security.AuthMiddleware)
	r.Use(csrf.Protect(csrfKey, csrf.Secure(false), csrf.CookieName("clph_csrf")))

	r.Get("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	r.Get("/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	r.Get("/", h.home)
	r.Get("/auth/login", h.login)

	r.Group(func(pr chi.Router) {
		pr.Use(security.RequireRole(domain.RoleAdministrator, domain.RoleAssessor))
		pr.Post("/assessments", h.createAssessment)
		pr.Post("/assessments/{id}/outcome", h.recordOutcome)
	})

	r.Group(func(pr chi.Router) {
		pr.Use(security.RequireRole(domain.RoleAdministrator, domain.RoleApprover))
		pr.Post("/assessments/{id}/approve", h.approve)
	})

	r.Group(func(pr chi.Router) {
		pr.Use(security.RequireRole(domain.RoleAdministrator, domain.RoleApprover, domain.RoleAssessor))
		pr.Post("/assessments/{id}/attest", h.attest)
		pr.Post("/assessments/{id}/publish", h.publish)
	})

	r.Group(func(pr chi.Router) {
		pr.Use(security.RequireRole(domain.RoleAdministrator, domain.RoleApprover, domain.RoleAssessor, domain.RoleViewer))
		pr.Get("/assessments", h.listAssessments)
		pr.Get("/assessments/{id}", h.getAssessment)
		pr.Get("/reports/{id}.json", h.reportJSON)
		pr.Get("/reports/{id}.html", h.reportHTML)
	})

	return r
}

func (h *Handler) home(w http.ResponseWriter, r *http.Request) {
	if err := h.tmpl.ExecuteTemplate(w, "index.html", map[string]any{"csrf": csrf.Token(r)}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	user := domain.User{
		GitHubUser:  q(r, "user", "sample.assessor"),
		Email:       q(r, "email", "sample@example.com"),
		OIDCSubject: q(r, "sub", "oidc:sample.assessor"),
		DisplayName: q(r, "name", q(r, "user", "sample.assessor")),
		Role:        domain.Role(q(r, "role", string(domain.RoleAssessor))),
	}
	logged, err := h.svc.Login(r.Context(), user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "clph_session", Value: fmt.Sprintf("%s|%s|%s|%s", logged.GitHubUser, logged.Email, logged.OIDCSubject, logged.Role), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, Path: "/"})
	http.Redirect(w, r, "/assessments", http.StatusFound)
}

func (h *Handler) createAssessment(w http.ResponseWriter, r *http.Request) {
	actor, _ := security.UserFromContext(r.Context())
	a := domain.Assessment{
		AssessmentID:     r.FormValue("assessment_id"),
		ReviewDate:       parseDate(r.FormValue("review_date")),
		OwnerUserID:      actor.ID,
		ArtefactName:     r.FormValue("artefact_name"),
		ArtefactType:     r.FormValue("artefact_type"),
		ArtefactDigest:   r.FormValue("artefact_digest"),
		ArtefactRegistry: r.FormValue("artefact_registry"),
		RepositoryURL:    r.FormValue("repository_url"),
	}
	if a.AssessmentID == "" {
		a.AssessmentID = fmt.Sprintf("SA-%d", time.Now().Unix())
	}
	if a.ReviewDate.IsZero() {
		a.ReviewDate = time.Now().UTC().AddDate(1, 0, 0)
	}
	created, err := h.svc.CreateAssessment(r.Context(), actor, a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/assessments/%d", created.ID), http.StatusFound)
}

func (h *Handler) listAssessments(w http.ResponseWriter, r *http.Request) {
	list, err := h.svc.ListAssessments(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.tmpl.ExecuteTemplate(w, "assessments.html", map[string]any{"items": list, "csrf": csrf.Token(r)}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) getAssessment(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	a, err := h.svc.GetAssessment(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := h.tmpl.ExecuteTemplate(w, "assessment_detail.html", map[string]any{"assessment": a, "csrf": csrf.Token(r)}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handler) recordOutcome(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	actor, _ := security.UserFromContext(r.Context())
	err := h.svc.RecordOutcome(r.Context(), actor, id,
		domain.Outcome(r.FormValue("outcome")),
		r.FormValue("rationale"),
		r.FormValue("controls"),
		domain.Pattern(r.FormValue("pattern")),
		r.FormValue("pattern_rationale"),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/assessments/%d", id), http.StatusFound)
}

func (h *Handler) approve(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	actor, _ := security.UserFromContext(r.Context())
	if err := h.svc.ApproveAssessment(r.Context(), actor, id, r.FormValue("comments")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/assessments/%d", id), http.StatusFound)
}

func (h *Handler) attest(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	actor, _ := security.UserFromContext(r.Context())
	att, err := h.svc.GenerateAndSignAttestation(r.Context(), actor, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(att.StatementJSON)
}

func (h *Handler) publish(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	actor, _ := security.UserFromContext(r.Context())
	if err := h.svc.PublishAttestation(r.Context(), actor, id, 0, r.FormValue("registry"), r.FormValue("artifact_ref")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, _ = w.Write([]byte("published"))
}

func (h *Handler) reportJSON(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	a, err := h.svc.GetAssessment(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a)
}

func (h *Handler) reportHTML(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	a, err := h.svc.GetAssessment(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := h.tmpl.ExecuteTemplate(w, "report.html", map[string]any{"assessment": a}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func q(r *http.Request, key, fallback string) string {
	v := r.URL.Query().Get(key)
	if v == "" {
		return fallback
	}
	return v
}

func parseDate(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	t, _ := time.Parse("2006-01-02", v)
	return t
}
