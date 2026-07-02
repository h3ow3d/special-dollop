# Data Model

The platform now persists inventory enrichment in PostgreSQL while retaining
in-memory assessment workflow state for active wizard sessions.

## ERD

```text
teams
  └─< inventory_items
        └─1 artifact_metadata
             └─< artifact_evidence
```

## Inventory Items

`inventory_items` remains the authoritative list of assessable software artifacts.

Key discovery-related fields:
- `registry`
- `package_name` (repository path)
- `reference`

## Artifact Metadata

`artifact_metadata` stores the latest OCI discovery snapshot for one inventory item.

| Field | Type | Description |
|---|---|---|
| inventory_item_id | bigint FK unique | Owning inventory item |
| registry | varchar | Registry host |
| repository | varchar | Repository path |
| reference | varchar | User-registered reference (tag or digest) |
| resolved_reference | text | Digest-pinned reference |
| digest | varchar | Resolved digest |
| media_type | varchar | Resolved manifest media type |
| artifact_type | varchar | OCI artifact type where present |
| size_bytes | bigint | Manifest size |
| discovery_status | varchar | `pending`, `success`, `warning`, `failed` |
| discovery_error | text | Last warning or failure details |
| last_discovered_at | timestamptz | Successful discovery timestamp |
| last_refresh_at | timestamptz | Last discovery attempt timestamp |

## Artifact Evidence

`artifact_evidence` stores OCI referrer inventory for the artifact metadata row.

| Field | Type | Description |
|---|---|---|
| artifact_metadata_id | bigint FK | Owning metadata snapshot |
| type | varchar | `signature`, `sbom`, `provenance`, `attestation` |
| name | varchar | Human-friendly title or artifact type |
| digest | varchar | Referrer digest |
| media_type | varchar | Referrer media type |
| artifact_type | varchar | OCI artifact type |
| annotations | jsonb | Persisted OCI annotations |
| created_at | timestamptz | Row creation timestamp |

## AssessmentState (in-memory only)

Assessment sessions remain in-memory while a workflow is active.

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
