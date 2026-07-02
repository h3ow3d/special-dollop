// Package attestation builds in-toto statements for CLPH suitability assessments.
package attestation

import (
"crypto/sha256"
"encoding/json"
"fmt"
"strings"
"time"

"github.com/h3ow3d/special-dollop/internal/domain"
)

// Builder constructs in-toto statements from completed assessment state.
type Builder struct{}

// NewBuilder returns a new Builder.
func NewBuilder() *Builder { return &Builder{} }

// Build generates the in-toto statement JSON for the given assessment state.
// The statement is later wrapped in a DSSE envelope by the service layer.
func (b *Builder) Build(state *domain.AssessmentState) ([]byte, error) {
if state.Outcome == nil || state.Pattern == nil {
return nil, fmt.Errorf("outcome and promotion pattern are required to generate attestation")
}

st := buildStatement(state)
return json.MarshalIndent(st, "", "  ")
}

// inTotoStatement is the in-toto Statement v1 structure.
// See: https://in-toto.io/Statement/v1
type inTotoStatement struct {
Type          string          `json:"_type"`
PredicateType string          `json:"predicateType"`
Subject       []inTotoSubject `json:"subject"`
Predicate     clphPredicate   `json:"predicate"`
}

type inTotoSubject struct {
Name   string            `json:"name"`
Digest map[string]string `json:"digest"`
}

// clphPredicate is the CLPH suitability assessment predicate.
// Predicate type: https://clph.internal/suitability/v1
type clphPredicate struct {
AssessmentMetadata assessmentMetadata `json:"assessmentMetadata"`
ArtefactMetadata   artefactMetadata   `json:"artefactMetadata"`
DecisionMetadata   decisionMetadata   `json:"decisionMetadata"`
AssessmentContent  assessmentContent  `json:"assessmentContent"`
IdentityMetadata   identityMetadata   `json:"identityMetadata"`
}

type assessmentMetadata struct {
AssessmentID   string `json:"assessmentId"`
AssessmentDate string `json:"assessmentDate"`
ReviewDate     string `json:"reviewDate"`
}

type artefactMetadata struct {
ArtifactName      string `json:"artifactName"`
ArtifactType      string `json:"artifactType"`
ArtifactDigest    string `json:"artifactDigest"`
ArtifactReference string `json:"artifactReference"`
Registry          string `json:"registry"`
}

type decisionMetadata struct {
Outcome          string `json:"outcome"`
OutcomeLabel     string `json:"outcomeLabel"`
PromotionPattern string `json:"promotionPattern"`
PatternLabel     string `json:"patternLabel"`
Rationale        string `json:"rationale"`
RequiredControls string `json:"requiredControls,omitempty"`
PatternRationale string `json:"patternRationale"`
}

type assessmentContent struct {
Sections     map[string]sectionEntry `json:"sections"`
Participants []participantEntry      `json:"participants"`
}

type sectionEntry struct {
Label           string          `json:"label"`
Notes           string          `json:"notes"`
DiscussionNotes string          `json:"discussionNotes,omitempty"`
Evidence        []evidenceEntry `json:"evidence,omitempty"`
}

type evidenceEntry struct {
Reference string `json:"reference"`
Reviewed  bool   `json:"reviewed"`
}

type participantEntry struct {
Name         string `json:"name"`
Role         string `json:"role"`
Organisation string `json:"organisation"`
}

type identityMetadata struct {
GitHubUsername string   `json:"githubUsername"`
DisplayName    string   `json:"displayName"`
Email          string   `json:"email"`
Organisation   string   `json:"organisation,omitempty"`
TeamMembership []string `json:"teamMembership,omitempty"`
OIDCSubject    string   `json:"oidcSubject"`
}

func buildStatement(state *domain.AssessmentState) inTotoStatement {
digestVal, digestKey := parseDigest(state.Artefact.Digest)

sections := make(map[string]sectionEntry, len(domain.AllSections))
for _, name := range domain.AllSections {
meta := domain.SectionMetadata[name]
resp := state.Sections[name]
ev := make([]evidenceEntry, 0, len(resp.Evidence))
for _, e := range resp.Evidence {
if e.Reference != "" {
ev = append(ev, evidenceEntry{Reference: e.Reference, Reviewed: e.Reviewed})
}
}
sections[string(name)] = sectionEntry{
Label:           meta.Label,
Notes:           resp.Notes,
DiscussionNotes: resp.DiscussionNotes,
Evidence:        ev,
}
}

participants := make([]participantEntry, 0, len(state.Participants))
for _, p := range state.Participants {
participants = append(participants, participantEntry{
Name:         p.Name,
Role:         p.Role,
Organisation: p.Organisation,
})
}

return inTotoStatement{
Type:          "https://in-toto.io/Statement/v1",
PredicateType: "https://clph.internal/suitability/v1",
Subject: []inTotoSubject{{
Name:   state.Artefact.Name,
Digest: map[string]string{digestKey: digestVal},
}},
Predicate: clphPredicate{
AssessmentMetadata: assessmentMetadata{
AssessmentID:   state.ID,
AssessmentDate: formatDate(state.AssessmentDate),
ReviewDate:     formatDate(state.ReviewDate),
},
ArtefactMetadata: artefactMetadata{
ArtifactName:      state.Artefact.Name,
ArtifactType:      state.Artefact.Type,
ArtifactDigest:    state.Artefact.Digest,
ArtifactReference: state.Artefact.Reference,
Registry:          state.Artefact.Registry,
},
DecisionMetadata: decisionMetadata{
Outcome:          string(*state.Outcome),
OutcomeLabel:     state.Outcome.Label(),
PromotionPattern: string(*state.Pattern),
PatternLabel:     state.Pattern.Label(),
Rationale:        state.OutcomeRationale,
RequiredControls: state.RequiredControls,
PatternRationale: state.PatternRationale,
},
AssessmentContent: assessmentContent{
Sections:     sections,
Participants: participants,
},
IdentityMetadata: identityMetadata{
GitHubUsername: state.User.GitHubUsername,
DisplayName:    state.User.DisplayName,
Email:          state.User.Email,
Organisation:   state.User.Organisation,
TeamMembership: state.User.TeamMembership,
OIDCSubject:    state.User.OIDCSubject,
},
},
}
}

// parseDigest returns (value, algorithm) from a digest string like "sha256:abc".
// If the value does not contain a colon, it is hashed with SHA-256.
func parseDigest(v string) (value, algo string) {
if idx := strings.Index(v, ":"); idx != -1 {
return v[idx+1:], v[:idx]
}
sum := sha256.Sum256([]byte(v))
return fmt.Sprintf("%x", sum), "sha256"
}

func formatDate(t time.Time) string {
if t.IsZero() {
return ""
}
return t.Format(time.RFC3339)
}
