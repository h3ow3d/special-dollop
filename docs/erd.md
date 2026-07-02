# Data Model

This application is stateless. There is no database and no persistent data model.

The only runtime state is:

- **Session cookie** — signed HTTP-only cookie that holds the authenticated GitHub user identity for the duration of the browser session.
- **In-memory assessment state** — an `AssessmentState` struct held in a process-local `session.Store` (keyed by session ID) for the duration of a single wizard run. It is discarded after the attestation is published.

## AssessmentState (in-memory only)

| Field | Type | Description |
|---|---|---|
| ID | string | UUID generated at wizard start |
| User | User | GitHub identity of the assessor |
| ArtefactInfo | ArtefactInfo | Target OCI artefact details |
| Sections | map[SectionName]SectionResponse | Wizard section responses |
| Participants | []Participant | Workshop participants |
| Outcome | Outcome | Human-selected outcome (A–D) |
| PromotionPattern | Pattern | Human-selected pattern (A–D) |
| Rationale | string | Assessor-provided rationale |
| CreatedAt / UpdatedAt | time.Time | Timestamps for the attestation |

## User (in-memory, stored in session cookie)

| Field | Type | Description |
|---|---|---|
| GitHubUsername | string | GitHub login |
| DisplayName | string | GitHub display name (falls back to login) |
| Email | string | Primary verified email |
| Organisation | string | Primary GitHub organisation |
| TeamMembership | []string | GitHub team slugs within the organisation |
| OIDCSubject | string | e.g. "github:username" |

## SectionResponse (value in Sections map)

| Field | Type | Description |
|---|---|---|
| Notes | string | Assessor's free-text notes |
| DiscussionNotes | string | Additional discussion points and follow-up items |
| Evidence | []EvidenceRef | Referenced evidence items |

## Authoritative Record

The completed assessment is transformed into a signed in-toto attestation and attached to the selected OCI artefact. **The OCI-attached attestation is the system of record.** No separate storage is required.
