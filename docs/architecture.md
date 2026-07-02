# CLPH Suitability Assessment Service – Architecture

## Overview

The CLPH Suitability Assessment Service is a **lightweight assessment and attestation generator**.

It is NOT a workflow engine, NOT an assessment repository, and NOT a governance management platform.

Its sole purpose:

1. Authenticate a user (GitHub OAuth).
2. Guide the user through a CLPH suitability assessment wizard.
3. Record assessment responses in memory.
4. Allow the user to select the assessment outcome.
5. Generate a suitability attestation (in-toto Statement v1).
6. Sign the attestation (Ed25519 in dev; Sigstore keyless in production).
7. Attach the attestation directly to an OCI artefact.
8. Exit.

The OCI artefact becomes the system of record.

## Design Principles

- **Stateless**: no database; assessment state lives only in server memory for the duration of a wizard run.
- **Human decisions**: the application never determines or recommends an outcome; it records the human decision.
- **The attestation is the record**: once attached to the OCI artefact, the signed attestation is authoritative. The server-side session can be discarded.

## Package Structure

```
cmd/clph-web/          – application entry point (wires dependencies)
internal/
  domain/              – core types (User, AssessmentState, Outcome, Pattern, Section*, etc.)
  app/                 – Service: orchestrates wizard flow, DSSE envelope construction
  infra/
    session/           – in-memory AssessmentState store (sync.Map)
    attestation/       – in-toto statement builder (full predicate)
    oci/               – OCI Publisher interface + stub implementation
    security/          – GitHub OAuth handler, session cookie, SecurityHeaders, RequireAuth
  web/                 – HTTP handler (wizard routes), HTML templates
```

## Authentication

GitHub OAuth 2.0 flow:
1. `/auth/login` → redirect to GitHub with random state
2. `/auth/callback` → exchange code, fetch user, set signed session cookie
3. User identity (username, email, OIDC subject) is stored in a signed Gorilla SecureCookie

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
- `assessmentContent`: sections (notes + evidence per section), participants
- `identityMetadata`: githubUsername, email, oidcSubject

## Signing

| Mode        | Implementation              | Config                          |
|-------------|-----------------------------|---------------------------------|
| Development | Ephemeral Ed25519 key       | Default                         |
| Production  | Sigstore keyless (planned)  | `SIGNING_MODE=prod` (future)    |

The `Signer` interface in `internal/app/service.go` isolates signing so the implementation can be replaced without changing business logic.

## OCI Integration

The `OCIPublisher` interface in `internal/app/service.go` is implemented by a stub for development. The stub logs the intended publish action.

Production implementations should use:
- **cosign attest** – for Sigstore-signed attestations
- **oras attach** – for ORAS v2 referrers API

The interface is designed to support Harbor, Quay, and OCI Distribution Registry.

## Local Development

```bash
cp .env.example .env
# Edit .env with your GitHub OAuth app credentials
docker compose up
open http://localhost:8080
```

Services started: `clph-web` + `registry` (local OCI registry on port 5000).

No database service.
