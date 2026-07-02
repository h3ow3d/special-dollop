package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/h3ow3d/special-dollop/internal/app"
	"github.com/h3ow3d/special-dollop/internal/domain"
)

type fakeRepo struct{}

func (f *fakeRepo) CreateAssessment(_ context.Context, in domain.Assessment) (domain.Assessment, error) {
	in.ID = 1
	return in, nil
}
func (f *fakeRepo) ListAssessments(_ context.Context) ([]domain.Assessment, error) {
	return []domain.Assessment{{ID: 1, AssessmentID: "SA-001", Status: domain.StatusDraft, ArtefactName: "orders-api"}}, nil
}
func (f *fakeRepo) GetAssessmentByID(_ context.Context, _ int64) (domain.Assessment, error) {
	o := domain.OutcomeA
	p := domain.PatternA
	return domain.Assessment{ID: 1, AssessmentID: "SA-001", Status: domain.StatusApproved, Outcome: &o, Pattern: &p, CreatedAt: time.Now().UTC(), ReviewDate: time.Now().UTC()}, nil
}
func (f *fakeRepo) UpdateOutcome(_ context.Context, _ int64, _ domain.Outcome, _, _ string, _ domain.Pattern, _ string, _ domain.AssessmentStatus) error {
	return nil
}
func (f *fakeRepo) AddApproval(_ context.Context, _ domain.Approval) error { return nil }
func (f *fakeRepo) SetAssessmentStatus(_ context.Context, _ int64, _ domain.AssessmentStatus) error {
	return nil
}
func (f *fakeRepo) SaveAttestation(_ context.Context, att domain.Attestation) (domain.Attestation, error) {
	return att, nil
}
func (f *fakeRepo) UpdateAttestationPublication(_ context.Context, _ int64, _, _ string, _ time.Time) error {
	return nil
}
func (f *fakeRepo) CreateOrUpdateUser(_ context.Context, user domain.User) (domain.User, error) {
	user.ID = 1
	return user, nil
}
func (f *fakeRepo) AppendAuditLog(_ context.Context, _ domain.AuditLog) error { return nil }

type fakeBuilder struct{}

func (f *fakeBuilder) Build(_ domain.Assessment, _ string) ([]byte, error) {
	return []byte(`{"ok":true}`), nil
}

type fakeSigner struct{}

func (f *fakeSigner) Sign(_ context.Context, _ []byte, _ domain.User) (string, error) {
	return "sig", nil
}

type fakePublisher struct{}

func (f *fakePublisher) Publish(_ context.Context, _, _ string, _ []byte) (string, error) {
	return "registry/ref", nil
}

func TestHealthLive(t *testing.T) {
	h, err := NewHandler(app.NewService(&fakeRepo{}, &fakeBuilder{}, &fakeSigner{}, &fakePublisher{}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	w := httptest.NewRecorder()
	h.Router([]byte("12345678901234567890123456789012")).ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}
