# Architecture Diagram

```mermaid
flowchart LR
  User[Governance User] -->|GitHub login| Web[Chi + HTMX Web App]
  Web --> Service[Application Service Layer]
  Service --> DB[(PostgreSQL)]
  Service --> Sign[Signer]
  Service --> OCI[OCI Publisher]
  Service --> Audit[(Audit Logs)]
  Sign --> Att[In-Toto Attestation]
  OCI --> Registry[(OCI Registry)]
```

Layers:

1. `internal/web` - routes, handlers, templates
2. `internal/app` - workflow orchestration (human-selected outcomes only)
3. `internal/domain` - core entities and enums
4. `internal/infra` - Postgres store, signing, OCI abstraction
