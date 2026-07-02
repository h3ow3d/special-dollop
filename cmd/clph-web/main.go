package main

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/h3ow3d/special-dollop/internal/app"
	"github.com/h3ow3d/special-dollop/internal/audit"
	"github.com/h3ow3d/special-dollop/internal/auth"
	"github.com/h3ow3d/special-dollop/internal/bootstrap"
	"github.com/h3ow3d/special-dollop/internal/database"
	"github.com/h3ow3d/special-dollop/internal/evidence"
	"github.com/h3ow3d/special-dollop/internal/infra/attestation"
	"github.com/h3ow3d/special-dollop/internal/infra/logging"
	"github.com/h3ow3d/special-dollop/internal/infra/oci"
	"github.com/h3ow3d/special-dollop/internal/infra/security"
	"github.com/h3ow3d/special-dollop/internal/infra/session"
	"github.com/h3ow3d/special-dollop/internal/inventory"
	"github.com/h3ow3d/special-dollop/internal/teams"
	"github.com/h3ow3d/special-dollop/internal/users"
	"github.com/h3ow3d/special-dollop/internal/web"
)

func main() {
	logger := logging.ConfigureFromEnv()
	logger.Info("application start")

	// Session store – in-memory only, no database
	store := session.NewStore()

	// Signing – ephemeral dev key; swap for Sigstore keyless in production
	signer, err := security.NewDevSigner()
	if err != nil {
		logger.Error("service initialization failed", "operation", "signer", "error", err.Error())
		os.Exit(1)
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
		logger.Warn("github oauth client id not set; oauth login will not work")
	}

	sessionHashKey := []byte(padTo32(getenv("SESSION_SECRET", "replace-me-with-32-byte-session-secret")))
	oauthHandler := security.NewOAuthHandler(oauthCfg, sessionHashKey)

	// HTTP handler
	h, err := web.NewHandler(svc, oauthHandler)
	if err != nil {
		logger.Error("service initialization failed", "operation", "web handler", "error", err.Error())
		os.Exit(1)
	}
	devMode := getenv("DEV_MODE", "false") == "true"
	h.WithDevelopmentMode(devMode)

	// PostgreSQL – required; provided by the Docker Compose stack.
	dsn := getenv("DATABASE_URL", "")
	if dsn == "" {
		logger.Error("database configuration missing", "operation", "database connection", "error", "DATABASE_URL is required")
		os.Exit(1)
	}
	logger.Info("database connection", "operation", "database connection")
	db, err := database.Open(dsn)
	if err != nil {
		logger.Error("database connection failed", "operation", "database connection", "error", err.Error())
		os.Exit(1)
	}
	logger.Info("database connected", "operation", "database connection")
	logger.Info("migrations start", "operation", "database migrations")
	if err := database.RunMigrations(db); err != nil {
		logger.Error("migrations failed", "operation", "database migrations", "error", err.Error())
		os.Exit(1)
	}
	logger.Info("migrations complete", "operation", "database migrations")

	// Repositories
	logger.Info("repository initialization")
	userRepo := users.NewUserRepository(db)
	roleRepo := users.NewRoleRepository(db)
	teamRepo := teams.NewRepository(db)
	auditRepo := audit.NewRepository(db)
	inventoryRepo := inventory.NewRepository(db)
	evidenceRepo := evidence.NewRepository(db)
	logger.Info("repository initialization complete")

	// Services
	logger.Info("service initialization")
	auditSvc := audit.NewService(auditRepo)
	userSvc := users.NewService(userRepo, roleRepo)
	teamSvc := teams.NewService(teamRepo)
	evidenceSvc := evidence.NewService(evidenceRepo, oci.NewDiscoverer(oci.PublisherConfig{
		Username:  getenv("OCI_USERNAME", ""),
		Password:  getenv("OCI_PASSWORD", ""),
		PlainHTTP: getenv("OCI_PLAIN_HTTP", "false") == "true",
	}))
	inventorySvc := inventory.NewService(inventoryRepo, evidenceSvc)
	logger.Info("service initialization complete")

	// Auth enricher: upserts DB user after GitHub OAuth.
	authSvc := auth.NewService(userSvc, teamRepo, auditSvc, auth.Config{
		BootstrapAdmins: parseCSV(getenv("BOOTSTRAP_ADMINS", "")),
	})
	oauthHandler.WithEnricher(authSvc)

	// Admin handler
	adminHandler := web.NewAdminHandler(h, userSvc, teamSvc, auditSvc)
	h.WithAdminHandler(adminHandler)

	// Inventory handler
	inventoryHandler := web.NewInventoryHandler(h, inventorySvc, teamSvc, auditSvc)
	h.WithInventoryHandler(inventoryHandler)

	// Bootstrap development users and teams when DEV_MODE=true.
	if devMode {
		seeder := bootstrap.NewSeeder(teamSvc, userSvc, inventorySvc)
		if err := seeder.Seed(context.Background()); err != nil {
			logger.Error("bootstrap failed", "operation", "bootstrap seeding", "error", err.Error())
			os.Exit(1)
		}
		logger.Info("bootstrap complete", "operation", "bootstrap seeding")
		loginSvc := bootstrap.NewLoginService(userSvc, teamRepo, auditSvc)
		h.WithDevLoginService(loginSvc)
	}

	csrfKey := []byte(padTo32(getenv("CSRF_AUTH_KEY", "replace-me-with-32-byte-csrf-secret")))
	addr := getenv("HTTP_ADDR", ":8080")

	s := &http.Server{
		Addr:              addr,
		Handler:           nil,
		ReadHeaderTimeout: 10 * time.Second,
	}
	logger.Info("route registration")
	s.Handler = h.Router(csrfKey)
	logger.Info("route registration complete")

	logger.Info("http server startup", "addr", addr)
	logger.Info("startup complete", "addr", addr)
	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("http server failed", "operation", "http server startup", "error", err.Error())
		os.Exit(1)
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

func parseCSV(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}
