package web

import (
"embed"
"encoding/json"
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
"github.com/h3ow3d/special-dollop/internal/domain"
"github.com/h3ow3d/special-dollop/internal/infra/security"
)

//go:embed templates/*.html
var templateFS embed.FS

// Handler wires HTTP routes to the assessment wizard service.
type Handler struct {
svc   *app.Service
oauth *security.OAuthHandler
tmpl  *template.Template
}

// NewHandler creates a Handler, parsing all embedded templates.
func NewHandler(svc *app.Service, oauth *security.OAuthHandler) (*Handler, error) {
tmpl, err := template.New("").Funcs(templateFuncs()).ParseFS(templateFS, "templates/*.html")
if err != nil {
return nil, err
}
return &Handler{svc: svc, oauth: oauth, tmpl: tmpl}, nil
}

func templateFuncs() template.FuncMap {
return template.FuncMap{
"add": func(a, b int) int { return a + b },
"sub": func(a, b int) int { return a - b },
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
r.Use(csrf.Protect(csrfKey, csrf.Secure(false), csrf.CookieName("clph_csrf")))

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

// Protected wizard routes
r.Group(func(pr chi.Router) {
pr.Use(security.RequireAuth)

pr.Get("/wizard", func(w http.ResponseWriter, r *http.Request) {
http.Redirect(w, r, "/wizard/new", http.StatusFound)
})
pr.Get("/wizard/new", h.wizardStart)
pr.Post("/wizard/new", h.wizardCreate)

pr.Get("/wizard/{id}/step/{n}", h.wizardStep)
pr.Post("/wizard/{id}/step/{n}", h.wizardStepSave)

pr.Get("/wizard/{id}/participants", h.wizardParticipants)
pr.Post("/wizard/{id}/participants/add", h.wizardAddParticipant)
pr.Post("/wizard/{id}/participants/remove/{n}", h.wizardRemoveParticipant)

pr.Get("/wizard/{id}/review", h.wizardReview)
pr.Get("/wizard/{id}/attest", h.wizardAttest)
pr.Post("/wizard/{id}/attest", h.wizardSign)

pr.Get("/wizard/{id}/publish", h.wizardPublish)
pr.Post("/wizard/{id}/publish", h.wizardPublishPost)

pr.Get("/wizard/{id}/done", h.wizardDone)

// OCI discovery
pr.Get("/oci/discover", h.ociDiscover)
pr.Post("/oci/resolve", h.ociResolve)

// Downloads
pr.Get("/wizard/{id}/download/envelope", h.downloadEnvelope)
pr.Get("/wizard/{id}/download/statement", h.downloadStatement)
pr.Get("/wizard/{id}/download/report", h.downloadReport)
})

return r
}

// ── Public handlers ──────────────────────────────────────────────────────────

func (h *Handler) home(w http.ResponseWriter, r *http.Request) {
user, ok := security.UserFromContext(r.Context())
if ok && user.GitHubUsername != "" {
http.Redirect(w, r, "/wizard", http.StatusFound)
return
}
h.render(w, r, "index.html", nil)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
http.SetCookie(w, &http.Cookie{Name: "clph_session", MaxAge: -1, Path: "/"})
http.Redirect(w, r, "/", http.StatusFound)
}

// ── Wizard handlers ──────────────────────────────────────────────────────────

func (h *Handler) wizardStart(w http.ResponseWriter, r *http.Request) {
h.render(w, r, "wizard_artefact.html", map[string]any{
"csrf": csrf.Token(r),
})
}

func (h *Handler) wizardCreate(w http.ResponseWriter, r *http.Request) {
user, _ := security.UserFromContext(r.Context())
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
Notes:    r.FormValue("notes"),
Evidence: parseEvidence(r.FormValue("evidence")),
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
user, ok := security.UserFromContext(r.Context())
if ok {
data["user"] = user
}
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
