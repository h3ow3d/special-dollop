package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/h3ow3d/special-dollop/internal/app"
	"github.com/h3ow3d/special-dollop/internal/infra/attestation"
	"github.com/h3ow3d/special-dollop/internal/infra/db"
	"github.com/h3ow3d/special-dollop/internal/infra/oci"
	"github.com/h3ow3d/special-dollop/internal/infra/security"
	"github.com/h3ow3d/special-dollop/internal/web"
)

func main() {
	ctx := context.Background()
	dbURL := getenv("DATABASE_URL", "postgres://localhost:5432/clph?sslmode=disable")
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("connect db: %v", err)
	}
	defer pool.Close()

	if err := runMigrations(dbURL); err != nil {
		log.Fatalf("migrations: %v", err)
	}

	store := db.NewStore(pool)
	if err := store.SeedSampleData(ctx); err != nil {
		log.Fatalf("seed: %v", err)
	}

	signer, err := security.NewSigner()
	if err != nil {
		log.Fatalf("signer: %v", err)
	}

	svc := app.NewService(store, attestation.NewBuilder(), signer, oci.NewPublisher())
	h, err := web.NewHandler(svc)
	if err != nil {
		log.Fatalf("handler: %v", err)
	}

	csrfKey := []byte(padTo32(getenv("CSRF_AUTH_KEY", "replace-me-with-32-byte-secret")))
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

func runMigrations(dbURL string) error {
	db, err := goose.OpenDBWithDriver("pgx", dbURL)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, "db/migrations")
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
