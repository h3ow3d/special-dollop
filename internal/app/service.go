package app

import (
"context"
"crypto/rand"
"encoding/base64"
"encoding/hex"
"encoding/json"
"errors"
"fmt"
"time"

"github.com/h3ow3d/special-dollop/internal/domain"
"github.com/h3ow3d/special-dollop/internal/infra/session"
)

// AttestationBuilder generates an in-toto statement from assessment state.
type AttestationBuilder interface {
Build(state *domain.AssessmentState) (statementJSON []byte, err error)
}

// Signer signs a payload and returns the base64-encoded signature.
type Signer interface {
Sign(ctx context.Context, payload []byte, user domain.User) (signature string, err error)
}

// OCIPublisher attaches a signed attestation envelope to an OCI artefact.
type OCIPublisher interface {
Publish(ctx context.Context, registry, ref string, envelope []byte) (ociRef string, err error)
}

// ErrNotFound is returned when the requested assessment session does not exist.
var ErrNotFound = errors.New("assessment not found")

// Service orchestrates the assessment wizard. It is stateless with respect to
// persistent storage: all assessment state lives in the in-memory session store.
type Service struct {
sessions  *session.Store
builder   AttestationBuilder
signer    Signer
publisher OCIPublisher
}

// NewService creates a Service wired to the provided dependencies.
func NewService(sessions *session.Store, builder AttestationBuilder, signer Signer, publisher OCIPublisher) *Service {
return &Service{sessions: sessions, builder: builder, signer: signer, publisher: publisher}
}

// StartAssessment initialises a new wizard session and returns the assessment state.
func (s *Service) StartAssessment(user domain.User, artefact domain.ArtefactInfo, reviewDate time.Time) (*domain.AssessmentState, error) {
id, err := newID()
if err != nil {
return nil, fmt.Errorf("generate assessment id: %w", err)
}
if reviewDate.IsZero() {
reviewDate = time.Now().UTC().AddDate(1, 0, 0)
}
state := &domain.AssessmentState{
ID:             id,
AssessmentDate: time.Now().UTC(),
ReviewDate:     reviewDate,
User:           user,
Artefact:       artefact,
Sections:       make(map[domain.SectionName]domain.SectionResponse),
}
s.sessions.Set(state)
return state, nil
}

// GetAssessment retrieves an active assessment session.
func (s *Service) GetAssessment(id string) (*domain.AssessmentState, error) {
state, ok := s.sessions.Get(id)
if !ok {
return nil, ErrNotFound
}
return state, nil
}

// UpdateSection saves the assessor's notes and evidence for a single section.
func (s *Service) UpdateSection(id string, sectionName domain.SectionName, resp domain.SectionResponse) error {
state, ok := s.sessions.Get(id)
if !ok {
return ErrNotFound
}
state.Sections[sectionName] = resp
s.sessions.Set(state)
return nil
}

// AddParticipant appends a workshop participant to the assessment.
func (s *Service) AddParticipant(id string, p domain.Participant) error {
state, ok := s.sessions.Get(id)
if !ok {
return ErrNotFound
}
state.Participants = append(state.Participants, p)
s.sessions.Set(state)
return nil
}

// RemoveParticipant removes the participant at the given index.
func (s *Service) RemoveParticipant(id string, index int) error {
state, ok := s.sessions.Get(id)
if !ok {
return ErrNotFound
}
if index < 0 || index >= len(state.Participants) {
return errors.New("participant index out of range")
}
state.Participants = append(state.Participants[:index], state.Participants[index+1:]...)
s.sessions.Set(state)
return nil
}

// SetOutcome records the human-selected suitability outcome and promotion pattern.
// The application never determines the outcome; it records the human decision.
func (s *Service) SetOutcome(id string, outcome domain.Outcome, rationale, controls string, pattern domain.Pattern, patternRationale string) error {
state, ok := s.sessions.Get(id)
if !ok {
return ErrNotFound
}
state.Outcome = &outcome
state.OutcomeRationale = rationale
state.RequiredControls = controls
state.Pattern = &pattern
state.PatternRationale = patternRationale
s.sessions.Set(state)
return nil
}

// GenerateAndSign builds the in-toto attestation, wraps it in a DSSE envelope,
// signs it, and stores the result on the session. This is the explicit sign step.
func (s *Service) GenerateAndSign(ctx context.Context, id string) (*domain.SignedAttestation, error) {
state, ok := s.sessions.Get(id)
if !ok {
return nil, ErrNotFound
}
if state.Outcome == nil || state.Pattern == nil {
return nil, errors.New("outcome and promotion pattern must be selected before signing")
}

statementJSON, err := s.builder.Build(state)
if err != nil {
return nil, fmt.Errorf("build attestation: %w", err)
}

sig, err := s.signer.Sign(ctx, statementJSON, state.User)
if err != nil {
return nil, fmt.Errorf("sign attestation: %w", err)
}

envelopeJSON, err := buildDSSEEnvelope(statementJSON, sig)
if err != nil {
return nil, fmt.Errorf("build dsse envelope: %w", err)
}

att := &domain.SignedAttestation{
StatementJSON: statementJSON,
EnvelopeJSON:  envelopeJSON,
Signature:     sig,
SignedBy:      state.User.GitHubUsername,
SignedEmail:   state.User.Email,
OIDCSubject:   state.User.OIDCSubject,
SigningTime:   time.Now().UTC(),
}
state.Attestation = att
s.sessions.Set(state)
return att, nil
}

// PublishAttestation attaches the signed attestation to the specified OCI artefact.
func (s *Service) PublishAttestation(ctx context.Context, id, registry, ref string) (string, error) {
state, ok := s.sessions.Get(id)
if !ok {
return "", ErrNotFound
}
if state.Attestation == nil {
return "", errors.New("attestation must be generated and signed before publishing")
}
ociRef, err := s.publisher.Publish(ctx, registry, ref, state.Attestation.EnvelopeJSON)
if err != nil {
return "", fmt.Errorf("publish attestation: %w", err)
}
state.Attestation.OCIReference = ociRef
s.sessions.Set(state)
return ociRef, nil
}

// dsseEnvelope is the Dead Simple Signing Envelope format.
// See: https://github.com/secure-systems-lab/dsse
type dsseEnvelope struct {
PayloadType string          `json:"payloadType"`
Payload     string          `json:"payload"`
Signatures  []dsseSignature `json:"signatures"`
}

type dsseSignature struct {
KeyID string `json:"keyid,omitempty"`
Sig   string `json:"sig"`
}

// buildDSSEEnvelope wraps a statement in a DSSE envelope with the provided signature.
func buildDSSEEnvelope(statementJSON []byte, sig string) ([]byte, error) {
env := dsseEnvelope{
PayloadType: "application/vnd.in-toto+json",
Payload:     base64.StdEncoding.EncodeToString(statementJSON),
Signatures:  []dsseSignature{{KeyID: "local-dev-key", Sig: sig}},
}
return json.Marshal(env)
}

// newID generates a cryptographically random 16-byte hex identifier.
func newID() (string, error) {
b := make([]byte, 16)
if _, err := rand.Read(b); err != nil {
return "", err
}
return hex.EncodeToString(b), nil
}
