package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/h3ow3d/special-dollop/internal/app"
	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/auth"
	"github.com/h3ow3d/special-dollop/internal/database"
	"github.com/h3ow3d/special-dollop/internal/infra/attestation"
	"github.com/h3ow3d/special-dollop/internal/infra/oci"
	"github.com/h3ow3d/special-dollop/internal/infra/security"
	"github.com/h3ow3d/special-dollop/internal/infra/session"
	"github.com/h3ow3d/special-dollop/internal/teams"
	"github.com/h3ow3d/special-dollop/internal/users"
	"github.com/h3ow3d/special-dollop/internal/web"
)

func main() {
	// Session store – in-memory only, no database
	store := session.NewStore()

	// Signing – ephemeral dev key; swap for Sigstore keyless in production
	signer, err := security.NewDevSigner()
	if err != nil {
		log.Fatalf("signer: %v", err)
	}

	// OCI publisher – uploads the signed DSSE envelope as an OCI referrer.
	publisher := oci.NewPublisher(oci.PublisherConfig{
		Username:  getenv("OCI_USERNAME", ""),
		Password:  getenv("OCI_PASSWORD", ""),
		PlainHTTP: getenv("OCI_PLAIN_HTTP", "false") == "true",
	})

	// Attestation builder
	builder := attestation.NewBuilder()

	// Service
	svc := app.NewService(store, builder, signer, publisher)

	// GitHub OAuth
	oauthCfg := security.GitHubOAuthConfig{
		ClientID:      getenv("GITHUB_CLIENT_ID", ""),
		ClientSecret:  getenv("GITHUB_CLIENT_SECRET", ""),
		RedirectURL:   getenv("GITHUB_REDIRECT_URL", "http://localhost:8080/auth/callback"),
		SecureCookies: getenv("SECURE_COOKIES", "false") == "true",
	}
	if oauthCfg.ClientID == "" {
		log.Println("WARNING: GITHUB_CLIENT_ID not set – OAuth login will not work")
	}

	sessionHashKey := []byte(padTo32(getenv("SESSION_SECRET", "replace-me-with-32-byte-session-secret")))
	oauthHandler := security.NewOAuthHandler(oauthCfg, sessionHashKey)

	// HTTP handler
	h, err := web.NewHandler(svc, oauthHandler)
	if err != nil {
		log.Fatalf("handler: %v", err)
	}
	h.WithDevelopmentMode(getenv("DEV_MODE", "false") == "true")

	// PostgreSQL – required; provided by the Docker Compose stack.
	dsn := getenv("DATABASE_URL", "")
	if dsn == "" {
		log.Fatalf("DATABASE_URL is required – start the application via Docker Compose so the database is available")
	}
	db, err := database.Open(dsn)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	if err := database.RunMigrations(db); err != nil {
		log.Fatalf("migrations: %v", err)
	}
	log.Println("database: migrations applied")

	// Repositories
	userRepo := users.NewUserRepository(db)
	roleRepo := users.NewRoleRepository(db)
	teamRepo := teams.NewRepository(db)
	auditRepo := audit.NewRepository(db)

	// Services
	auditSvc := audit.NewService(auditRepo)
	userSvc := users.NewService(userRepo, roleRepo)
	teamSvc := teams.NewService(teamRepo)

	// Auth enricher: upserts DB user after GitHub OAuth.
	authSvc := auth.NewService(userSvc, teamRepo, auditSvc)
	oauthHandler.WithEnricher(authSvc)

	// Admin handler
	adminHandler := web.NewAdminHandler(h, userSvc, teamSvc, auditSvc)
	h.WithAdminHandler(adminHandler)

	csrfKey := []byte(padTo32(getenv("CSRF_AUTH_KEY", "replace-me-with-32-byte-csrf-secret")))
	addr := getenv("HTTP_ADDR", ":8080")

	s := &http.Server{
		Addr:              addr,
		Handler:           h.Router(csrfKey),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("clph service listening on %s", addr)
	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}

func getenv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func padTo32(v string) string {
	if len(v) >= 32 {
		return v[:32]
	}
	return v + strings.Repeat("x", 32-len(v))
}
