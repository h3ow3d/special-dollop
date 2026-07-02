package evidence

import "time"

// DiscoveryStatus captures the most recent discovery result for an artifact digest.
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

// ArtifactDigest is an immutable, content-addressed anchor for an OCI image.
// One row per unique digest per inventory item. Rows are never deleted so
// that assessment records referencing them remain valid indefinitely.
type ArtifactDigest struct {
	ID               int64
	InventoryItemID  int64
	Digest           string // sha256:…
	MediaType        string
	ArtifactType     string
	SizeBytes        int64
	DiscoveryStatus  DiscoveryStatus
	DiscoveryError   string
	LastDiscoveredAt time.Time
	LastRefreshAt    time.Time
	CreatedAt        time.Time
	Evidence         []*DigestEvidence // populated on detail queries
	Tags             []string          // populated via JOIN for display
}

// RepositoryTag links a mutable OCI tag to an immutable ArtifactDigest.
type RepositoryTag struct {
	ID               int64
	InventoryItemID  int64
	Tag              string
	ArtifactDigestID *int64    // nil until the tag has been successfully resolved
	FirstSeenAt      time.Time
	LastSeenAt       time.Time
	Digest           string // denormalized from artifact_digests; empty if unresolved
}

// DigestEvidence stores one discovered signature, SBOM, provenance record, or
// attestation referrer associated with an immutable artifact digest.
type DigestEvidence struct {
	ID               int64
	ArtifactDigestID int64
	Type             EvidenceType
	Name             string
	Digest           string
	MediaType        string
	ArtifactType     string
	Annotations      map[string]string
	CreatedAt        time.Time
}

// DiscoveryTarget defines the OCI repository to inspect for all available tags.
type DiscoveryTarget struct {
	InventoryItemID int64
	Registry        string
	Repository      string
}

// TagResolution holds the resolved metadata for a single OCI tag.
type TagResolution struct {
	Tag          string
	Digest       string
	MediaType    string
	ArtifactType string
	SizeBytes    int64
}

// RepositorySummary holds discovery statistics for an inventory item,
// used for efficient display in list views.
type RepositorySummary struct {
	InventoryItemID  int64
	TagCount         int
	DigestCount      int
	LastDiscoveredAt time.Time
	OverallStatus    DiscoveryStatus
}
