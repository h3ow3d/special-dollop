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
| GET | `/wizard` | Start a new assessment (step 1 — Artefact Information) |
| POST | `/wizard/start` | Submit step 1 and create the in-memory AssessmentState |
| GET | `/wizard/step/{n}` | Render wizard step n (2–10) |
| POST | `/wizard/step/{n}` | Submit wizard step n |
| GET | `/wizard/participants` | Participant management page |
| POST | `/wizard/participants` | Add a participant |
| DELETE | `/wizard/participants/{i}` | Remove participant at index i |
| GET | `/wizard/review` | Pre-sign review summary |
| GET | `/wizard/attest` | Generate & Sign Attestation page |
| POST | `/wizard/attest` | Generate and cryptographically sign the attestation |
| GET | `/wizard/publish` | Select OCI artefact and publish page |
| POST | `/wizard/publish` | Attach signed attestation to the selected OCI artefact |
| GET | `/wizard/done` | Success and download page |

### Downloads (convenience copies only)

| Method | Path | Description |
|---|---|---|
| GET | `/download/attestation.json` | Raw in-toto statement JSON |
| GET | `/download/envelope.json` | Full DSSE envelope JSON |
| GET | `/download/report.html` | Human-readable HTML report |

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
