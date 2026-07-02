# HTTP Routes

## Public

| Method | Path | Description |
|---|---|---|
| GET | `/` | Landing / login page |
| GET | `/health/live` | Liveness probe |
| GET | `/health/ready` | Readiness probe |
| GET | `/auth/login` | Redirects to GitHub OAuth authorisation |
| GET | `/auth/callback` | GitHub OAuth callback — sets signed session cookie and redirects to `/wizard` |

## Authenticated (requires valid session cookie and an assigned role)

### Wizard

| Method | Path | Description | Roles |
|---|---|---|---|
| GET | `/wizard` | Dashboard / assessment start page | Administrator, Assessor, Reader |
| GET | `/wizard/new` | Artefact Information form (step 1) | Administrator, Assessor, Reader |
| POST | `/wizard/new` | Submit step 1, create in-memory AssessmentState, redirect to step 2 | Administrator, Assessor |
| GET | `/wizard/{id}/step/{n}` | Render wizard step n (2–10) | Administrator, Assessor, Reader |
| POST | `/wizard/{id}/step/{n}` | Submit wizard step n | Administrator, Assessor |
| GET | `/wizard/{id}/participants` | Participant management page | Administrator, Assessor, Reader |
| POST | `/wizard/{id}/participants/add` | Add a participant | Administrator, Assessor |
| POST | `/wizard/{id}/participants/remove/{n}` | Remove participant at index n | Administrator, Assessor |
| GET | `/wizard/{id}/review` | Pre-sign review summary | Administrator, Assessor, Reader |
| GET | `/wizard/{id}/attest` | Generate & Sign Attestation page | Administrator, Assessor, Reader |
| POST | `/wizard/{id}/attest` | Generate and cryptographically sign the attestation | Administrator, Assessor |
| GET | `/wizard/{id}/publish` | Publish attestation page | Administrator, Assessor, Reader |
| POST | `/wizard/{id}/publish` | Attach signed attestation to the selected OCI artefact | Administrator, Assessor |
| GET | `/wizard/{id}/done` | Success and download page | Administrator, Assessor, Reader |

### Downloads (convenience copies only)

| Method | Path | Description | Roles |
|---|---|---|---|
| GET | `/wizard/{id}/download/envelope` | Full DSSE envelope JSON | Administrator, Assessor, Reader |
| GET | `/wizard/{id}/download/statement` | Raw in-toto statement JSON | Administrator, Assessor, Reader |
| GET | `/wizard/{id}/download/report` | Human-readable HTML report | Administrator, Assessor, Reader |

### OCI Discovery

| Method | Path | Description | Roles |
|---|---|---|---|
| GET | `/oci/discover` | OCI registry browser (enter URL, browse repos and tags) | Administrator, Assessor, Reader |
| POST | `/oci/resolve` | Resolve a tag to its digest | Administrator, Assessor, Reader |

### Session

| Method | Path | Description | Roles |
|---|---|---|---|
| GET | `/auth/logout` | Clear session cookie and redirect to `/` | Administrator, Assessor, Reader |
| POST | `/auth/logout` | Clear session cookie and redirect to `/` | Administrator, Assessor, Reader |

## Administrator

| Method | Path | Description |
|---|---|---|
| GET | `/admin/users` | User administration page |
| POST | `/admin/users/{id}/activate` | Activate a user |
| POST | `/admin/users/{id}/deactivate` | Deactivate a user |
| POST | `/admin/users/{id}/role` | Update a user's role |
| POST | `/admin/users/{id}/team` | Update a user's team |
| GET | `/admin/teams` | Team administration page |
| POST | `/admin/teams` | Create a team |
| GET | `/admin/roles` | View seeded roles |

## Attestation Format

In-toto Statement v1 wrapped in a DSSE envelope with predicate type:

```
https://clph.internal/suitability/v1
```

See [architecture.md](architecture.md) for the full predicate schema.
