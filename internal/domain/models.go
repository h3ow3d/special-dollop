package domain

import "time"

type Role string

const (
	RoleAdministrator Role = "Administrator"
	RoleAssessor      Role = "Assessor"
	RoleApprover      Role = "Approver"
	RoleViewer        Role = "Viewer"
)

type AssessmentStatus string

const (
	StatusDraft      AssessmentStatus = "Draft"
	StatusInReview   AssessmentStatus = "In Review"
	StatusApproved   AssessmentStatus = "Approved"
	StatusRejected   AssessmentStatus = "Rejected"
	StatusSuperseded AssessmentStatus = "Superseded"
)

type Outcome string

const (
	OutcomeA Outcome = "OutcomeA"
	OutcomeB Outcome = "OutcomeB"
	OutcomeC Outcome = "OutcomeC"
	OutcomeD Outcome = "OutcomeD"
)

type Pattern string

const (
	PatternA Pattern = "PatternA"
	PatternB Pattern = "PatternB"
	PatternC Pattern = "PatternC"
	PatternD Pattern = "PatternD"
)

type User struct {
	ID          int64
	GitHubUser  string
	Email       string
	OIDCSubject string
	DisplayName string
	Role        Role
	CreatedAt   time.Time
	LastLoginAt *time.Time
	SoftDeleted *time.Time
}

type Assessment struct {
	ID                  int64
	AssessmentID        string
	Status              AssessmentStatus
	CreatedAt           time.Time
	ReviewDate          time.Time
	OwnerUserID         int64
	ArtefactName        string
	ArtefactType        string
	ArtefactDigest      string
	ArtefactRegistry    string
	RepositoryURL       string
	SensitivityNotes    string
	PrivilegeNotes      string
	ProvenanceNotes     string
	VerifiabilityNotes  string
	TraceabilityNotes   string
	OperationalNotes    string
	RecoverabilityNotes string
	SupplyChainNotes    string
	Outcome             *Outcome
	OutcomeRationale    string
	RequiredControls    string
	Pattern             *Pattern
	PatternRationale    string
	DeletedAt           *time.Time
}

type Participant struct {
	ID           int64
	AssessmentID int64
	Name         string
	Email        string
	Role         string
	Organisation string
}

type Evidence struct {
	ID           int64
	AssessmentID int64
	Type         string
	Reviewed     bool
	Reference    string
}

type Note struct {
	ID                int64
	AssessmentID      int64
	DiscussionSummary string
	Concerns          string
	Assumptions       string
	Constraints       string
	Rationale         string
}

type Approval struct {
	ID               int64
	AssessmentID     int64
	ApproverName     string
	ApproverIdentity string
	ApproverRole     string
	ApprovalTime     time.Time
	ApprovalComments string
}

type Attestation struct {
	ID            int64
	AssessmentID  int64
	StatementJSON []byte
	Signature     string
	SignedBy      string
	SignedEmail   string
	OIDCSubject   string
	SigningTime   time.Time
	OCIReference  string
	OCIRegistry   string
	PublishedAt   *time.Time
}

type AuditLog struct {
	ID          int64
	ActorUserID *int64
	EventType   string
	EntityType  string
	EntityID    string
	OccurredAt  time.Time
	Payload     string
}
