package security

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"

	"github.com/h3ow3d/special-dollop/internal/domain"
)

type Signer struct {
	priv ed25519.PrivateKey
}

func NewSigner() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{priv: priv}, nil
}

func (s *Signer) Sign(_ context.Context, payload []byte, _ domain.User) (string, error) {
	sig := ed25519.Sign(s.priv, payload)
	return base64.StdEncoding.EncodeToString(sig), nil
}
