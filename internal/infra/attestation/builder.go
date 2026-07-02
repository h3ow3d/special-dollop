package attestation

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/h3ow3d/special-dollop/internal/domain"
)

type Builder struct{}

func NewBuilder() *Builder { return &Builder{} }

func (b *Builder) Build(a domain.Assessment, approver string) ([]byte, error) {
	if a.Outcome == nil || a.Pattern == nil {
		return nil, fmt.Errorf("assessment requires outcome and pattern")
	}

	type predicate struct {
		AssessmentID   string `json:"assessmentId"`
		ArtifactName   string `json:"artifactName"`
		ArtifactType   string `json:"artifactType"`
		ArtifactDigest string `json:"artifactDigest"`
		Outcome        string `json:"outcome"`
		Pattern        string `json:"pattern"`
		AssessmentDate string `json:"assessmentDate"`
		ReviewDate     string `json:"reviewDate"`
		Assessor       string `json:"assessor"`
		Approver       string `json:"approver"`
	}
	type statement struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
		Subject       []any  `json:"subject"`
		Predicate     any    `json:"predicate"`
	}

	subject := map[string]any{
		"name": a.ArtefactName,
		"digest": map[string]string{
			"sha256": trimDigest(a.ArtefactDigest),
		},
	}

	st := statement{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: "https://clph.internal/suitability/v1",
		Subject:       []any{subject},
		Predicate: predicate{
			AssessmentID:   a.AssessmentID,
			ArtifactName:   a.ArtefactName,
			ArtifactType:   a.ArtefactType,
			ArtifactDigest: a.ArtefactDigest,
			Outcome:        string(*a.Outcome),
			Pattern:        string(*a.Pattern),
			AssessmentDate: a.CreatedAt.Format("2006-01-02"),
			ReviewDate:     a.ReviewDate.Format("2006-01-02"),
			Assessor:       approver,
			Approver:       approver,
		},
	}
	return json.Marshal(st)
}

func trimDigest(v string) string {
	const prefix = "sha256:"
	if len(v) > len(prefix) && v[:len(prefix)] == prefix {
		return v[len(prefix):]
	}
	sum := sha256.Sum256([]byte(v))
	return base64.StdEncoding.EncodeToString(sum[:])[:32]
}
