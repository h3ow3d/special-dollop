package app

import (
"context"
"testing"
"time"

"github.com/h3ow3d/special-dollop/internal/domain"
"github.com/h3ow3d/special-dollop/internal/infra/session"
)

type fakeBuilder struct{}

func (f *fakeBuilder) Build(_ *domain.AssessmentState) ([]byte, error) {
return []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://clph.internal/suitability/v1"}`), nil
}

type fakeSigner struct{}

func (f *fakeSigner) Sign(_ context.Context, _ []byte, _ domain.User) (string, error) {
return "dGVzdHNpZw==", nil // base64 "testsig"
}

type fakePublisher struct{}

func (f *fakePublisher) Publish(_ context.Context, _, _ string, _ []byte, _, _ string) (string, error) {
return "registry.local/repo@sha256:abc123", nil
}

func newTestService() *Service {
return NewService(session.NewStore(), &fakeBuilder{}, &fakeSigner{}, &fakePublisher{})
}

func TestStartAssessment(t *testing.T) {
svc := newTestService()
user := domain.User{GitHubUsername: "sam", Email: "sam@example.com", OIDCSubject: "github:sam"}
artefact := domain.ArtefactInfo{Name: "orders-api", Type: "application-container", Digest: "sha256:abc"}
state, err := svc.StartAssessment(user, artefact, time.Time{})
if err != nil {
t.Fatalf("StartAssessment: %v", err)
}
if state.ID == "" {
t.Fatal("expected non-empty assessment ID")
}
if state.User.GitHubUsername != "sam" {
t.Fatalf("expected user sam got %s", state.User.GitHubUsername)
}
}

func TestUpdateSection(t *testing.T) {
svc := newTestService()
user := domain.User{GitHubUsername: "sam"}
state, _ := svc.StartAssessment(user, domain.ArtefactInfo{Name: "x"}, time.Time{})

err := svc.UpdateSection(state.ID, domain.SectionSensitivity, domain.SectionResponse{
Notes: "sensitive data processed",
})
if err != nil {
t.Fatalf("UpdateSection: %v", err)
}

got, _ := svc.GetAssessment(state.ID)
if got.Sections[domain.SectionSensitivity].Notes != "sensitive data processed" {
t.Fatalf("unexpected notes: %s", got.Sections[domain.SectionSensitivity].Notes)
}
}

func TestSetOutcomeAndGenerateAndSign(t *testing.T) {
svc := newTestService()
user := domain.User{GitHubUsername: "sam", Email: "sam@example.com"}
state, _ := svc.StartAssessment(user, domain.ArtefactInfo{Name: "x"}, time.Time{})

// GenerateAndSign should fail without an outcome
if _, err := svc.GenerateAndSign(context.Background(), state.ID); err == nil {
t.Fatal("expected error when outcome not set")
}

if err := svc.SetOutcome(state.ID, domain.OutcomeA, "rationale", "", domain.PatternA, "justification"); err != nil {
t.Fatalf("SetOutcome: %v", err)
}

att, err := svc.GenerateAndSign(context.Background(), state.ID)
if err != nil {
t.Fatalf("GenerateAndSign: %v", err)
}
if att.SignedBy != "sam" {
t.Fatalf("expected SignedBy=sam got %s", att.SignedBy)
}
if len(att.EnvelopeJSON) == 0 {
t.Fatal("expected non-empty DSSE envelope")
}
}

func TestPublishRequiresAttestation(t *testing.T) {
svc := newTestService()
state, _ := svc.StartAssessment(domain.User{}, domain.ArtefactInfo{Name: "x"}, time.Time{})
if _, err := svc.PublishAttestation(context.Background(), state.ID, "registry.local", "repo:tag"); err == nil {
t.Fatal("expected error when attestation not yet generated")
}
}

func TestAddRemoveParticipant(t *testing.T) {
svc := newTestService()
state, _ := svc.StartAssessment(domain.User{}, domain.ArtefactInfo{Name: "x"}, time.Time{})

_ = svc.AddParticipant(state.ID, domain.Participant{Name: "Alice", Role: "Assessor", Organisation: "Acme"})
_ = svc.AddParticipant(state.ID, domain.Participant{Name: "Bob", Role: "Observer", Organisation: "Corp"})

got, _ := svc.GetAssessment(state.ID)
if len(got.Participants) != 2 {
t.Fatalf("expected 2 participants, got %d", len(got.Participants))
}

_ = svc.RemoveParticipant(state.ID, 0)
got, _ = svc.GetAssessment(state.ID)
if len(got.Participants) != 1 || got.Participants[0].Name != "Bob" {
t.Fatalf("expected only Bob remaining, got %+v", got.Participants)
}
}

func TestGetAssessmentNotFound(t *testing.T) {
svc := newTestService()
if _, err := svc.GetAssessment("nonexistent"); err == nil {
t.Fatal("expected ErrNotFound")
}
}
