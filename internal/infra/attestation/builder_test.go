package attestation

import (
"encoding/json"
"testing"
"time"

"github.com/h3ow3d/special-dollop/internal/domain"
)

func TestBuilderBuild(t *testing.T) {
o := domain.OutcomeA
p := domain.PatternB
b := NewBuilder()

state := &domain.AssessmentState{
ID:             "test-id-001",
AssessmentDate: time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC),
ReviewDate:     time.Date(2027, 7, 2, 0, 0, 0, 0, time.UTC),
User:           domain.User{GitHubUsername: "sam.holden", Email: "sam@example.com", OIDCSubject: "github:sam.holden"},
Artefact: domain.ArtefactInfo{
Name:      "orders-api",
Type:      "application-container",
Digest:    "sha256:abc123",
Reference: "registry.local/orders-api:v1.0.0",
Registry:  "registry.local",
},
Sections: map[domain.SectionName]domain.SectionResponse{
domain.SectionSensitivity: {Notes: "Processes PII data", Evidence: []domain.EvidenceRef{{Reference: "https://jira/SEC-001", Reviewed: true}}},
},
Participants: []domain.Participant{{Name: "Alice", Role: "Assessor", Organisation: "Acme"}},
Outcome:      &o,
Pattern:      &p,
OutcomeRationale: "Comprehensive controls verified",
PatternRationale: "Standard promotion path applies",
}

payload, err := b.Build(state)
if err != nil {
t.Fatalf("build: %v", err)
}

var decoded map[string]any
if err := json.Unmarshal(payload, &decoded); err != nil {
t.Fatalf("unmarshal: %v", err)
}
if decoded["predicateType"] != "https://clph.internal/suitability/v1" {
t.Fatalf("unexpected predicateType: %v", decoded["predicateType"])
}
if decoded["_type"] != "https://in-toto.io/Statement/v1" {
t.Fatalf("unexpected _type: %v", decoded["_type"])
}

pred, ok := decoded["predicate"].(map[string]any)
if !ok {
t.Fatal("predicate missing")
}

// Check decision metadata
dm, ok := pred["decisionMetadata"].(map[string]any)
if !ok {
t.Fatal("decisionMetadata missing")
}
if dm["outcome"] != "OutcomeA" {
t.Fatalf("expected OutcomeA got %v", dm["outcome"])
}

// Check identity metadata
im, ok := pred["identityMetadata"].(map[string]any)
if !ok {
t.Fatal("identityMetadata missing")
}
if im["githubUsername"] != "sam.holden" {
t.Fatalf("expected sam.holden got %v", im["githubUsername"])
}

// Check assessment content
ac, ok := pred["assessmentContent"].(map[string]any)
if !ok {
t.Fatal("assessmentContent missing")
}
participants, ok := ac["participants"].([]any)
if !ok || len(participants) != 1 {
t.Fatal("expected 1 participant")
}
}

func TestBuilderRequiresOutcomeAndPattern(t *testing.T) {
b := NewBuilder()
state := &domain.AssessmentState{
ID:       "x",
Sections: make(map[domain.SectionName]domain.SectionResponse),
}
if _, err := b.Build(state); err == nil {
t.Fatal("expected error when outcome/pattern not set")
}
}

func TestParseDigest(t *testing.T) {
cases := []struct {
input string
algo  string
}{
{"sha256:abc123", "sha256"},
{"sha512:def456", "sha512"},
{"nodialect", "sha256"}, // falls back to sha256 hash
}
for _, c := range cases {
_, algo := parseDigest(c.input)
if algo != c.algo {
t.Errorf("parseDigest(%q) algo=%q want %q", c.input, algo, c.algo)
}
}
}
