package domain

import "time"

// Outcome is a human-selected suitability decision.
// The application never determines the outcome; it only records it.
type Outcome string

const (
	OutcomeA Outcome = "OutcomeA" // Suitable for Promotion
	OutcomeB Outcome = "OutcomeB" // Suitable with Additional Controls
	OutcomeC Outcome = "OutcomeC" // Hybrid Treatment Required
	OutcomeD Outcome = "OutcomeD" // Higher Assurance Treatment Required
)

// Pattern is a human-selected promotion pattern.
type Pattern string

const (
	PatternA Pattern = "PatternA"
	PatternB Pattern = "PatternB"
	PatternC Pattern = "PatternC"
	PatternD Pattern = "PatternD"
)

// User is an authenticated GitHub user. Identity fields become attestation metadata.
type User struct {
	GitHubUsername string
	DisplayName    string
	Email          string
	AvatarURL      string
	Organisation   string   // primary GitHub organisation
	TeamMembership []string // GitHub team slugs within the organisation
	OIDCSubject    string   // e.g. "github:<username>"
	GitHubToken    string   // OAuth access token; used for OCI registry operations
}

// UserSession carries authenticated user identity and RBAC state through the
// request context. It is stored in the encrypted session cookie.
type UserSession struct {
	GitHubUser      User   // GitHub identity; also used for attestation metadata
	UserID          int64  // platform database user ID (0 when DB is not configured)
	RoleID          int64  // stored platform role ID; 0 when DB is not configured
	RoleSlug        string // stored platform role slug: "administrator" | "assessor" | "reader" | ""
	LastVisitedPath string
	TeamID          *int64 // nil when no team is assigned
	TeamName        string // empty when no team is assigned
	AuthSource      string // "" for GitHub OAuth; "dev" for development login
	LoginAt         time.Time
	Active          bool
}

// EffectiveUserID returns the active platform user ID for the session.
func (s UserSession) EffectiveUserID() int64 {
	return s.UserID
}

// EffectiveRoleSlug returns the active role for request authorization.
func (s UserSession) EffectiveRoleSlug() string {
	return s.RoleSlug
}

// EffectiveTeamName returns the active team name for the session.
func (s UserSession) EffectiveTeamName() string {
	return s.TeamName
}

// ArtefactInfo describes the target OCI artefact being assessed.
type ArtefactInfo struct {
	Name      string // human-readable name
	Type      string // e.g. "application-container", "helm-chart"
	Digest    string // sha256:...
	Reference string // full registry reference, e.g. registry/repo:tag
	Registry  string // registry host
}

// SectionName identifies an assessment section.
type SectionName string

const (
	SectionSensitivity       SectionName = "sensitivity"
	SectionPrivilege         SectionName = "privilege"
	SectionProvenance        SectionName = "provenance"
	SectionVerifiability     SectionName = "verifiability"
	SectionTraceability      SectionName = "traceability"
	SectionOperationalImpact SectionName = "operational_impact"
	SectionRecoverability    SectionName = "recoverability"
	SectionSupplyChain       SectionName = "supply_chain"
)

// AllSections is the ordered list of the eight assessment sections.
var AllSections = []SectionName{
	SectionSensitivity,
	SectionPrivilege,
	SectionProvenance,
	SectionVerifiability,
	SectionTraceability,
	SectionOperationalImpact,
	SectionRecoverability,
	SectionSupplyChain,
}

// SectionMeta holds display metadata for a section.
type SectionMeta struct {
	Label    string
	Guidance string
}

// SectionMetadata maps each section to its display label and guidance text.
var SectionMetadata = map[SectionName]SectionMeta{
	SectionSensitivity: {
		Label:    "Sensitivity",
		Guidance: "Consider the classification and sensitivity of data processed or stored by this artefact. Assess whether the artefact handles personal, commercially sensitive, or government-classified data, and the implications of exposure.",
	},
	SectionPrivilege: {
		Label:    "Privilege",
		Guidance: "Assess the privilege level required to operate this artefact. Consider whether it runs with elevated permissions, accesses privileged APIs, or has the ability to affect other systems or users.",
	},
	SectionProvenance: {
		Label:    "Provenance",
		Guidance: "Evaluate the origin and build history of the artefact. Consider whether it was built from trusted sources, whether the build process is documented and reproducible, and whether upstream dependencies are known.",
	},
	SectionVerifiability: {
		Label:    "Verifiability",
		Guidance: "Assess the degree to which the artefact and its provenance can be independently verified. Consider the presence of signatures, SBOMs, build attestations, and whether verification tooling is available.",
	},
	SectionTraceability: {
		Label:    "Traceability",
		Guidance: "Evaluate the traceability of the artefact from source to deployment. Consider whether commits, issues, approvals, and build steps are all linked and auditable.",
	},
	SectionOperationalImpact: {
		Label:    "Operational Impact",
		Guidance: "Assess the potential operational impact if this artefact were to behave incorrectly or be compromised. Consider blast radius, dependencies, and the criticality of the services it supports.",
	},
	SectionRecoverability: {
		Label:    "Recoverability",
		Guidance: "Evaluate how readily the organisation could recover from a failure or compromise of this artefact. Consider rollback capabilities, backup procedures, incident response plans, and recovery time objectives.",
	},
	SectionSupplyChain: {
		Label:    "Supply Chain Assurance",
		Guidance: "Assess the security posture of the supply chain for this artefact. Consider third-party component risk, dependency scanning, vendor assurance, and adherence to supply chain security frameworks.",
	},
}

// EvidenceRef is a reference to evidence reviewed during the assessment.
type EvidenceRef struct {
	Reference string
	Reviewed  bool
}

// SectionResponse captures the assessor's notes, discussion, and evidence for one section.
type SectionResponse struct {
	Notes           string
	DiscussionNotes string
	Evidence        []EvidenceRef
}

// Participant is a workshop participant recorded for informational purposes.
type Participant struct {
	Name         string
	Role         string
	Organisation string
}

// AssessmentState is the in-memory wizard state for a single assessment run.
// It is ephemeral: once the attestation is published, this state is no longer needed.
type AssessmentState struct {
	ID               string
	InventoryItemID  int64  // links this assessment to a registered inventory item
	ArtifactDigestID int64  // links to the immutable digest being assessed
	AssessmentDate   time.Time
	ReviewDate       time.Time
	User             User
	Artefact         ArtefactInfo
	Sections         map[SectionName]SectionResponse
	Participants     []Participant
	Outcome          *Outcome
	OutcomeRationale string
	RequiredControls string
	Pattern          *Pattern
	PatternRationale string
	// Attestation is set after Generate & Sign
	Attestation *SignedAttestation
}

// SignedAttestation is the completed DSSE-wrapped and signed attestation.
type SignedAttestation struct {
	EnvelopeJSON  []byte // complete DSSE envelope (authoritative record)
	StatementJSON []byte // inner in-toto statement (for human-readable download)
	Signature     string
	SignedBy      string
	SignedEmail   string
	OIDCSubject   string
	SigningTime   time.Time
	OCIReference  string // set after OCI publication
}

// OutcomeLabel returns the human-readable label for an outcome.
func (o Outcome) Label() string {
	switch o {
	case OutcomeA:
		return "Outcome A – Suitable for Promotion"
	case OutcomeB:
		return "Outcome B – Suitable with Additional Controls"
	case OutcomeC:
		return "Outcome C – Hybrid Treatment Required"
	case OutcomeD:
		return "Outcome D – Higher Assurance Treatment Required"
	default:
		return string(o)
	}
}

// PatternLabel returns the human-readable label for a pattern.
func (p Pattern) Label() string {
	switch p {
	case PatternA:
		return "Pattern A"
	case PatternB:
		return "Pattern B"
	case PatternC:
		return "Pattern C"
	case PatternD:
		return "Pattern D"
	default:
		return string(p)
	}
}
