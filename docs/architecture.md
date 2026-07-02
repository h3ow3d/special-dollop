# CLPH Suitability Assessment Service – Architecture

## Overview

The CLPH Suitability Assessment Service is an **inventory-led evidence discovery, assessment, and attestation platform**.

It is NOT a workflow engine, NOT an assessment repository, and NOT a governance management platform.

Its core purpose:

1. Authenticate a user (GitHub OAuth).
2. Register OCI artifacts in inventory as the authoritative source of truth.
3. Discover artifact metadata and OCI evidence (signatures, SBOMs, provenance, attestations).
4. Guide the user through a CLPH suitability assessment wizard using discovered evidence.
5. Record assessment responses in memory.
6. Generate a suitability attestation (in-toto Statement v1).
7. Sign the attestation (Ed25519 in dev; Sigstore keyless in production).
8. Attach the attestation directly to the assessed OCI artefact.

Inventory becomes the authoritative catalog of artifact identity and evidence. OCI-attached attestations remain the signed outcome record.

## Design Principles

- **Inventory-first**: artifact registration and evidence discovery happen before assessment.
- **Persistent evidence**: inventory enrichment is stored in PostgreSQL.
- **Ephemeral assessments**: assessment state lives only in server memory for the duration of a wizard run.
- **Human decisions**: the application never determines or recommends an outcome; it records the human decision.
- **The attestation is the record**: once attached to the OCI artefact, the signed attestation is authoritative. The server-side session can be discarded.

## Package Structure

```
cmd/clph-web/          – application entry point (wires dependencies)
internal/
  domain/              – core types (User, AssessmentState, Outcome, Pattern, Section*, etc.)
  app/                 – Service: orchestrates wizard flow, DSSE envelope construction
  evidence/            – Artifact metadata/evidence persistence and discovery orchestration
  infra/
    session/           – in-memory AssessmentState store (sync.Map)
    attestation/       – in-toto statement builder (full predicate)
    oci/               – OCI publisher plus reusable OCI discovery client
    security/          – GitHub OAuth handler, session cookie, SecurityHeaders, RequireAuth
  web/                 – HTTP handler (wizard routes), HTML templates
```

## Authentication

GitHub OAuth 2.0 flow:
1. `/auth/login` → redirect to GitHub with random state (scopes: `user:email read:org`)
2. `/auth/callback` → exchange code, fetch user, set signed session cookie
3. User identity (username, display name, email, organisation, team membership, OIDC subject) is stored in a signed Gorilla SecureCookie

## Inventory Enrichment

Inventory items capture:
- registry
- repository
- reference

Creation, update, and manual refresh all trigger OCI discovery. The discovery service:
- resolves the digest
- inspects manifest metadata
- enumerates OCI referrers
- classifies signatures, SBOMs, provenance, and attestations

The resulting metadata and evidence are persisted for later assessment and reporting.

## Assessment Wizard

Steps:

| Step | Route                         | Purpose                    |
|------|-------------------------------|----------------------------|
| 1    | `GET/POST /wizard/new`        | Artefact Information       |
| 2–9  | `GET/POST /wizard/{id}/step/n`| Assessment sections        |
| 10   | `GET/POST /wizard/{id}/step/10`| Outcome and Rationale     |
| –    | `/wizard/{id}/participants`   | Workshop participant list  |
| –    | `/wizard/{id}/review`         | Review before signing      |
| –    | `POST /wizard/{id}/attest`    | Generate & Sign            |
| –    | `POST /wizard/{id}/publish`   | Attach to OCI artefact     |
| –    | `/wizard/{id}/done`           | Success + downloads        |

## Attestation Format

**in-toto Statement v1** wrapped in a **DSSE envelope**:

```
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64(statement)>",
  "signatures": [{ "keyid": "local-dev-key", "sig": "<base64(ed25519sig)>" }]
}
```

Predicate type: `https://clph.internal/suitability/v1`

Predicate fields:
- `assessmentMetadata`: assessmentId, assessmentDate, reviewDate
- `artefactMetadata`: name, type, digest, reference, registry
- `decisionMetadata`: outcome, outcomeLabel, promotionPattern, rationale, requiredControls
- `assessmentContent`: sections (notes + discussionNotes + evidence per section), participants
- `identityMetadata`: githubUsername, displayName, email, organisation, teamMembership, oidcSubject

## Signing

| Mode        | Implementation              | Config                          |
|-------------|-----------------------------|---------------------------------|
| Development | Ephemeral Ed25519 key       | Default                         |
| Production  | Sigstore keyless (planned)  | `SIGNING_MODE=prod` (future)    |

The `Signer` interface in `internal/app/service.go` isolates signing so the implementation can be replaced without changing business logic.

## OCI Integration

The primary OCI registry is **GitHub Container Registry (GHCR)** (e.g. `ghcr.io/company/orders-api`).

The `OCIPublisher` interface in `internal/app/service.go` is implemented by an ORAS-backed publisher that uploads the DSSE envelope as an OCI referrer attached to the assessed artefact.

Current publication behaviour:
- **ORAS / OCI 1.1 referrers** – attaches the DSSE envelope to the target artefact
- **Registry auth via environment variables** – `OCI_USERNAME` and `OCI_PASSWORD`
- **Predicate annotation** – the CLPH predicate type is recorded in manifest annotations for easier discovery

The interface is designed so that Fulcio and Rekor can be added later without changing business logic.

## Local Development

```bash
cp .env.example .env
# Edit .env with your GitHub OAuth app credentials
docker compose up
open http://localhost:8080
```

Services started: `clph-web` only.

No database service. No local registry. The application connects directly to GitHub APIs and GitHub Container Registry.
