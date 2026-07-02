package security

import (
"context"
"crypto/ed25519"
"crypto/rand"
"encoding/base64"

"github.com/h3ow3d/special-dollop/internal/domain"
)

// DevSigner signs payloads with an ephemeral Ed25519 key.
// This is development-mode only; the key is generated fresh on every startup.
//
// For production, replace with a Sigstore keyless signer backed by GitHub OIDC.
// Keep this interface identical so the implementation can be swapped later.
type DevSigner struct {
priv ed25519.PrivateKey
}

// NewDevSigner generates an ephemeral Ed25519 signing key and returns a DevSigner.
func NewDevSigner() (*DevSigner, error) {
_, priv, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
return nil, err
}
return &DevSigner{priv: priv}, nil
}

// Sign signs the payload with the ephemeral Ed25519 key and returns a base64-encoded signature.
// The user parameter is included for interface compatibility with production signers
// that incorporate identity into the signing ceremony.
func (s *DevSigner) Sign(_ context.Context, payload []byte, _ domain.User) (string, error) {
sig := ed25519.Sign(s.priv, payload)
return base64.StdEncoding.EncodeToString(sig), nil
}
