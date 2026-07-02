# Deployment Guide

## Local Development

1. Copy the example environment file and fill in your GitHub OAuth app credentials:

   ```bash
   cp .env.example .env
   ```

2. Start the application:

   ```bash
   docker compose up --build
   ```

3. Open `http://localhost:8080`

The docker compose stack starts:
- `clph-web` — the Go web application
- `registry` — a local OCI registry (CNCF Distribution, port 5000)

No database service is required.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GITHUB_CLIENT_ID` | Yes | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | Yes | GitHub OAuth App client secret |
| `GITHUB_REDIRECT_URL` | Yes | OAuth callback URL (e.g. `http://localhost:8080/auth/callback`) |
| `CSRF_AUTH_KEY` | Yes | 32-byte key for CSRF token signing (hex or raw) |
| `SESSION_SECRET` | Yes | 32-byte key for session cookie signing |
| `SECURE_COOKIES` | No | Set to `"true"` in production (HTTPS). Default: `"false"` |
| `PORT` | No | Listen port. Default: `8080` |

## Container Image

Build:

```bash
docker build -t clph-web:latest .
```

Run:

```bash
docker run --rm -p 8080:8080 --env-file .env clph-web:latest
```

## Future Kubernetes

The service is stateless by design and suitable for Kubernetes deployment with:

- Deployment for `clph-web` (multiple replicas are safe — no shared in-process state between pods is required for completed assessments; in-progress wizard state is per-session and short-lived)
- OCI registry integration (Harbor, Quay, or OCI Distribution)
- Kubernetes Secrets for OAuth credentials, CSRF key, and session secret
- Ingress with TLS termination (set `SECURE_COOKIES=true`)

No database, no migration job, no seed data required.
