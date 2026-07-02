# Deployment Guide

## Local

1. `cp .env.example .env`
2. `docker compose up --build`
3. Open `http://localhost:8080`

The app auto-runs migrations and seeds sample data at startup.

## Container runtime

Build image:

`docker build -t clph-web:latest .`

Run:

`docker run --rm -p 8080:8080 --env-file .env clph-web:latest`

## Future Kubernetes

The service is stateless and suitable for Kubernetes migration with:

- Deployment for `clph-web`
- StatefulSet/managed PostgreSQL
- OCI registry service integration
- secret-managed CSRF and DB credentials
