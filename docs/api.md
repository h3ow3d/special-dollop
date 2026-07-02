# HTTP Routes

## Public

| Method | Path | Description |
|---|---|---|
| GET | `/` | Landing / login page |
| GET | `/health/live` | Liveness probe |
| GET | `/health/ready` | Readiness probe |
| GET | `/auth/login` | Redirects to GitHub OAuth authorisation |
| GET | `/auth/callback` | GitHub OAuth callback — sets signed session cookie and redirects to `/wizard` |

## Authenticated (requires valid session cookie)

### Wizard

| Method | Path | Description |
|---|---|---|
| GET | `/wizard` | Redirect to `/wizard/new` |
| GET | `/wizard/new` | Artefact Information form (step 1) |
| POST | `/wizard/new` | Submit step 1, create in-memory AssessmentState, redirect to step 2 |
| GET | `/wizard/{id}/step/{n}` | Render wizard step n (2–10) |
| POST | `/wizard/{id}/step/{n}` | Submit wizard step n |
| GET | `/wizard/{id}/participants` | Participant management page |
| POST | `/wizard/{id}/participants/add` | Add a participant |
| POST | `/wizard/{id}/participants/remove/{n}` | Remove participant at index n |
| GET | `/wizard/{id}/review` | Pre-sign review summary |
| GET | `/wizard/{id}/attest` | Generate & Sign Attestation page |
| POST | `/wizard/{id}/attest` | Generate and cryptographically sign the attestation |
| GET | `/wizard/{id}/publish` | Publish attestation page |
| POST | `/wizard/{id}/publish` | Attach signed attestation to the selected OCI artefact |
| GET | `/wizard/{id}/done` | Success and download page |

### Downloads (convenience copies only)

| Method | Path | Description |
|---|---|---|
| GET | `/wizard/{id}/download/envelope` | Full DSSE envelope JSON |
| GET | `/wizard/{id}/download/statement` | Raw in-toto statement JSON |
| GET | `/wizard/{id}/download/report` | Human-readable HTML report |

### OCI Discovery

| Method | Path | Description |
|---|---|---|
| GET | `/oci/discover` | OCI registry browser (enter URL, browse repos and tags) |
| GET | `/oci/resolve` | Resolve a tag to its digest |

### Session

| Method | Path | Description |
|---|---|---|
| POST | `/auth/logout` | Clear session cookie and redirect to `/` |

## Attestation Format

In-toto Statement v1 wrapped in a DSSE envelope with predicate type:

```
https://clph.internal/suitability/v1
```

See [architecture.md](architecture.md) for the full predicate schema.
