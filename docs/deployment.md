# Deployment Guide

## Local Development

1. Create a GitHub OAuth App for local development:

   1. Go to `https://github.com/settings/developers`.
   2. Open **OAuth Apps** and select **New OAuth App**.
   3. Set **Homepage URL** to `http://localhost:8080`.
   4. Set **Authorization callback URL** to `http://localhost:8080/auth/callback`.
   5. Create the app, then copy the generated **Client ID** and **Client Secret**.

   This service uses a GitHub OAuth App for sign-in. A GitHub App is not required.

2. Copy the example environment file:

   ```bash
   cp .env.example .env
   ```

3. Edit `.env` and set:

   - `GITHUB_CLIENT_ID` to the OAuth App client ID
   - `GITHUB_CLIENT_SECRET` to the OAuth App client secret
   - `GITHUB_REDIRECT_URL` to `http://localhost:8080/auth/callback`
   - `CSRF_AUTH_KEY` to a random 32-byte secret
   - `SESSION_SECRET` to a random 32-byte secret

   You can generate the two local secrets with:

   ```bash
   openssl rand -hex 32
   openssl rand -hex 32
   ```

4. Start the application:

   ```bash
   docker compose up --build
   ```

5. Open `http://localhost:8080`

The docker compose stack starts:
- `clph-web` — the Go web application

No database service is required. No local registry is required. The application connects directly to GitHub APIs and GitHub Container Registry (GHCR).

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
