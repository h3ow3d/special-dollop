# CLPH Suitability Assessment Service

Production-focused Go web application supporting the **Code Low Push High (CLPH)** suitability assessment workflow.

## What this service does

The system enables authorised governance personnel to:

- create and review suitability assessments
- record workshop evidence, discussion inputs, outcomes, and approvals
- generate and cryptographically sign In-Toto suitability attestations
- publish attestations to OCI references
- retain permanent assessment history and immutable audit logs

> The service does **not** calculate risk scores and does **not** automatically determine suitability outcomes.

## Stack

- Go 1.25+
- Chi Router, HTMX, html/template, TailwindCSS
- PostgreSQL
- Goose migrations
- sqlc query definitions
- Docker / Docker Compose

## Quick start

```bash
cp .env.example .env
docker compose up --build
```

Web app: http://localhost:8080

Login shortcut (local):

`/auth/login?user=sam.holden&email=sam@example.com&sub=oidc:sam.holden&role=Assessor`

## Services

- `clph-web`
- `postgres`
- `registry`

## Health

- `/health/live`
- `/health/ready`

## Roles (RBAC)

- Administrator
- Assessor
- Approver
- Viewer

## States

- Draft
- In Review
- Approved
- Rejected
- Superseded

Only **Approved** assessments can produce attestations.

## Reports

- HTML report: `/reports/{id}.html`
- JSON report: `/reports/{id}.json`
- Attestation JSON: POST `/assessments/{id}/attest`

## Security controls included

- secure HTTP-only session cookie
- CSRF protection
- CSP and hardened response headers
- full append-only audit event capture
- soft-delete schema (no hard-delete operations)

## Documentation

- [Architecture](docs/architecture.md)
- [Database ERD](docs/erd.md)
- [API documentation](docs/api.md)
- [Deployment guide](docs/deployment.md)
