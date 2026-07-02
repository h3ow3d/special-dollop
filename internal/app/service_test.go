package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/h3ow3d/special-dollop/internal/domain"
)

type fakeRepo struct {
	assessment domain.Assessment
	approved   bool
}

func (f *fakeRepo) CreateAssessment(_ context.Context, in domain.Assessment) (domain.Assessment, error) {
	return in, nil
}
func (f *fakeRepo) ListAssessments(_ context.Context) ([]domain.Assessment, error) { return nil, nil }
func (f *fakeRepo) GetAssessmentByID(_ context.Context, _ int64) (domain.Assessment, error) {
	return f.assessment, nil
}
func (f *fakeRepo) UpdateOutcome(_ context.Context, _ int64, _ domain.Outcome, _, _ string, _ domain.Pattern, _ string, _ domain.AssessmentStatus) error {
	return nil
}
func (f *fakeRepo) AddApproval(_ context.Context, _ domain.Approval) error { return nil }
func (f *fakeRepo) SetAssessmentStatus(_ context.Context, _ int64, status domain.AssessmentStatus) error {
	f.assessment.Status = status
	return nil
}
func (f *fakeRepo) SaveAttestation(_ context.Context, att domain.Attestation) (domain.Attestation, error) {
	att.ID = 1
	return att, nil
}
func (f *fakeRepo) GetAttestationByID(_ context.Context, _ int64) (domain.Attestation, error) {
	return domain.Attestation{ID: 1, AssessmentID: 42, StatementJSON: []byte(`{"x":1}`)}, nil
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
	return []byte(`{"x":1}`), nil
}

type fakeSigner struct{}

func (f *fakeSigner) Sign(_ context.Context, _ []byte, _ domain.User) (string, error) {
	return "sig", nil
}

type fakePublisher struct{}

func (f *fakePublisher) Publish(_ context.Context, _, _ string, _ []byte) (string, error) {
	return "registry/repo@sha256:1", nil
}

func TestGenerateAndSignAttestationRequiresApproved(t *testing.T) {
	o := domain.OutcomeA
	p := domain.PatternA
	repo := &fakeRepo{assessment: domain.Assessment{ID: 42, Status: domain.StatusDraft, Outcome: &o, Pattern: &p}}
	svc := NewService(repo, &fakeBuilder{}, &fakeSigner{}, &fakePublisher{})

	_, err := svc.GenerateAndSignAttestation(context.Background(), domain.User{GitHubUser: "sam"}, 42)
	if !errors.Is(err, ErrNotApproved) {
		t.Fatalf("expected ErrNotApproved got %v", err)
	}
}
