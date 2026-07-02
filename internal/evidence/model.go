package evidence

import "time"

// DiscoveryStatus captures the most recent metadata discovery result.
type DiscoveryStatus string

const (
	DiscoveryStatusPending DiscoveryStatus = "pending"
	DiscoveryStatusSuccess DiscoveryStatus = "success"
	DiscoveryStatusWarning DiscoveryStatus = "warning"
	DiscoveryStatusFailed  DiscoveryStatus = "failed"
)

// EvidenceType identifies a discovered OCI evidence category.
type EvidenceType string

const (
	EvidenceTypeSignature   EvidenceType = "signature"
	EvidenceTypeSBOM        EvidenceType = "sbom"
	EvidenceTypeProvenance  EvidenceType = "provenance"
	EvidenceTypeAttestation EvidenceType = "attestation"
)

// ArtifactMetadata stores the current discovery snapshot for an inventory item.
type ArtifactMetadata struct {
	ID                int64
	InventoryItemID   int64
	Registry          string
	Repository        string
	Reference         string
	ResolvedReference string
	Digest            string
	MediaType         string
	ArtifactType      string
	SizeBytes         int64
	DiscoveryStatus   DiscoveryStatus
	DiscoveryError    string
	LastDiscoveredAt  time.Time
	LastRefreshAt     time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Evidence          []*ArtifactEvidence
}

// ArtifactEvidence stores one discovered signature, SBOM, provenance record,
// or attestation associated with an inventory item.
type ArtifactEvidence struct {
	ID                 int64
	ArtifactMetadataID int64
	Type               EvidenceType
	Name               string
	Digest             string
	MediaType          string
	ArtifactType       string
	Annotations        map[string]string
	CreatedAt          time.Time
}

// DiscoveryTarget defines the registry coordinates to inspect.
type DiscoveryTarget struct {
	InventoryItemID int64
	Registry        string
	Repository      string
	Reference       string
}

// DiscoveryResult is the reusable output from an OCI discovery operation.
type DiscoveryResult struct {
	Registry          string
	Repository        string
	Reference         string
	ResolvedReference string
	Digest            string
	MediaType         string
	ArtifactType      string
	SizeBytes         int64
	Evidence          []*ArtifactEvidence
	Warnings          []string
}
