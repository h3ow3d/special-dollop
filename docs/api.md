# API Documentation

## Health
- `GET /health/live`
- `GET /health/ready`

## Authentication
- `GET /auth/login?user=&email=&sub=&role=` (local GitHub/OIDC simulation)

## Assessments
- `GET /assessments`
- `POST /assessments`
- `GET /assessments/{id}`
- `POST /assessments/{id}/outcome`
- `POST /assessments/{id}/approve`

## Attestations
- `POST /assessments/{id}/attest`
- `POST /assessments/{id}/publish`

## Reports
- `GET /reports/{id}.json`
- `GET /reports/{id}.html`

### Attestation format
In-Toto Statement v1 with predicate type:

`https://clph.internal/suitability/v1`
