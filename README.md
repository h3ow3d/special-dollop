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

## Development mode (`DEV_MODE=true`)

When `DEV_MODE=true` the application automatically seeds a set of development
teams and users on startup, and exposes a development login form on the home
page.  **Do not enable this in production.**

### Bootstrap teams

Four teams are created idempotently at startup:

| Team | Description |
|------|-------------|
| Platform Team | Platform engineering and shared services |
| Applications Team | Business applications and services |
| Security Team | Security tooling, governance and assurance |
| Data Team | Data platforms and analytics services |

### Bootstrap users

Ten users are created idempotently at startup, one per role/team combination
needed for POC testing:

| Display name | Username | Role | Team |
|---|---|---|---|
| Sam Holden | sam.holden | Administrator | Platform Team |
| Alex Carter | alex.carter | Assessor | Platform Team |
| Jordan Smith | jordan.smith | Reader | Platform Team |
| Taylor Brown | taylor.brown | Assessor | Applications Team |
| Morgan Wilson | morgan.wilson | Reader | Applications Team |
| Jamie Walker | jamie.walker | Reader | Applications Team |
| Casey Thomas | casey.thomas | Assessor | Security Team |
| Riley White | riley.white | Reader | Security Team |
| Avery Green | avery.green | Assessor | Data Team |
| Drew Hall | drew.hall | Reader | Data Team |

All users are active and have `@dev.local` e-mail addresses.  Seeding is
idempotent — running the application multiple times will not create
duplicates, and any manual changes made to dev users after first boot are
preserved on subsequent restarts.

### Development login workflow

A **Development Login** panel is shown on the home page.  Select any
bootstrap user from the dropdown and click **Sign In**.  A normal
authenticated session is created — the same session model, RBAC rules and
audit logging that apply to GitHub OAuth users apply equally to development
sessions.

Once signed in, a **Developer Tools** panel in the top navigation bar shows:

- **Current User** — display name
- **Role** — current effective role
- **Team** — assigned team
- **Authentication Source** — `Development Login` (or `GitHub OAuth`)

Audit events `dev.login` and `dev.logout` are recorded whenever a
development user signs in or out.

### Purpose

The development identities provide a realistic organisation structure for
testing RBAC, administration, team management and user management workflows
during the POC without needing multiple GitHub accounts, direct database
edits or manual user creation.

### Disabling the feature

Set `DEV_MODE=false` (or remove the variable entirely — the default is
`false`).  No bootstrap users or teams will be created, the development
login panel will not appear and no `dev.login`/`dev.logout` audit events
will be emitted.

## Documentation

- [Architecture](docs/architecture.md)
- [Data Model](docs/erd.md)
- [API / Routes](docs/api.md)
- [Deployment Guide](docs/deployment.md)
