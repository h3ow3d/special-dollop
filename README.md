# CLPH Suitability Assessment Service

A lightweight, stateless Go web application that guides governance personnel through a **Code Low Push High (CLPH)** suitability assessment, generates a signed in-toto attestation, and attaches it directly to an OCI artefact.

## What this service does

1. Authenticate a user via GitHub OAuth.
2. Guide the user through a 10-section suitability assessment wizard.
3. Record assessment responses, notes, evidence references, and participants.
4. Allow the user to select the assessment outcome (A–D) and promotion pattern.
5. Generate a signed DSSE-wrapped in-toto attestation.
6. Attach the attestation directly to the selected OCI artefact.

The OCI-attached attestation is the authoritative record. No database is required.

## Stack

- Go 1.25+
- Chi router, html/template, TailwindCSS, HTMX
- GitHub OAuth (authentication)
- gorilla/csrf, gorilla/securecookie
- Docker / Docker Compose
- Local OCI registry (CNCF Distribution)

## Quick start

```bash
cp .env.example .env
# Edit .env — add your GitHub OAuth App credentials
docker compose up --build
```

Open `http://localhost:8080`, authenticate with GitHub, then run through the wizard.

## Services (docker compose)

| Service | Description |
|---|---|
| `clph-web` | Go web application (port 8080) |
| `registry` | Local OCI registry (port 5000) |

## Wizard sections

1. Artefact Information
2. Sensitivity
3. Privilege
4. Provenance
5. Verifiability
6. Traceability
7. Operational Impact
8. Recoverability
9. Supply Chain Assurance
10. Outcome and Rationale

## Outcome selection

The assessor selects one of:

| Outcome | Label |
|---|---|
| A | Suitable for Promotion |
| B | Suitable with Additional Controls |
| C | Hybrid Treatment Required |
| D | Higher Assurance Treatment Required |

The application records the human decision. It never determines the outcome automatically.

## Downloads (after publication)

- Attestation JSON
- DSSE Envelope JSON
- Human-readable HTML report

These are convenience copies. The OCI-attached attestation is the authoritative record.

## Health

- `GET /health/live`
- `GET /health/ready`

## Security controls

- GitHub OAuth authentication
- Signed HTTP-only session cookie
- CSRF protection (gorilla/csrf)
- Content-Security-Policy and hardened response headers
- Configurable `Secure` cookie flag (set `SECURE_COOKIES=true` in production)

## Documentation

- [Architecture](docs/architecture.md)
- [Data Model](docs/erd.md)
- [API / Routes](docs/api.md)
- [Deployment Guide](docs/deployment.md)
