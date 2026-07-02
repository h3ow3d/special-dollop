package main

import (
"log"
"net/http"
"os"
"strings"
"time"

"github.com/h3ow3d/special-dollop/internal/app"
"github.com/h3ow3d/special-dollop/internal/infra/attestation"
"github.com/h3ow3d/special-dollop/internal/infra/oci"
"github.com/h3ow3d/special-dollop/internal/infra/security"
"github.com/h3ow3d/special-dollop/internal/infra/session"
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

// OCI publisher – stub for development; swap for cosign/ORAS in production
publisher := oci.NewStubPublisher()

// Attestation builder
builder := attestation.NewBuilder()

// Service
svc := app.NewService(store, builder, signer, publisher)

// GitHub OAuth
oauthCfg := security.GitHubOAuthConfig{
ClientID:     getenv("GITHUB_CLIENT_ID", ""),
ClientSecret: getenv("GITHUB_CLIENT_SECRET", ""),
RedirectURL:  getenv("GITHUB_REDIRECT_URL", "http://localhost:8080/auth/callback"),
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
