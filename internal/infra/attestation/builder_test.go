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

	payload, err := b.Build(domain.Assessment{
		AssessmentID:   "SA-001",
		ArtefactName:   "orders-api",
		ArtefactType:   "application-container",
		ArtefactDigest: "sha256:abc123",
		CreatedAt:      time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC),
		ReviewDate:     time.Date(2027, 7, 2, 0, 0, 0, 0, time.UTC),
		Outcome:        &o,
		Pattern:        &p,
	}, "sam.holden")
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["predicateType"] != "https://clph.internal/suitability/v1" {
		t.Fatalf("unexpected predicate type: %v", decoded["predicateType"])
	}
}
