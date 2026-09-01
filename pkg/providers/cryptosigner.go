package providers

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// FromCryptoSigner adapts an any crypto.Signer, to a Signer
// including: *rsa.PrivateKey, *ecdsa.PrivateKey or ed25519.PrivateKey
func FromCryptoSigner(name string, key crypto.Signer) (Signer, error) {
	inner, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		return nil, fmt.Errorf("build ssh signer: %w", err)
	}
	return &cryptoSigner{name: name, inner: inner}, nil
}

type cryptoSigner struct {
	name  string
	inner ssh.Signer
}

func (s *cryptoSigner) Name() string { return s.name }

func (s *cryptoSigner) PublicKey() ssh.PublicKey { return s.inner.PublicKey() }

func (s *cryptoSigner) Algorithms() []string {
	return AlgorithmsFor(s.inner.PublicKey().Type())
}

func (s *cryptoSigner) Sign(_ context.Context, algorithm string, data []byte) (*ssh.Signature, error) {
	keyType := s.inner.PublicKey().Type()

	// ECDSA and Ed25519 have exactly one algorithm, addressed by the key type
	// itself; only RSA needs an explicit rsa-sha2-* choice.
	if algorithm == "" || algorithm == keyType {
		return s.inner.Sign(rand.Reader, data)
	}
	as, ok := s.inner.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf("%s signer cannot produce %q signatures", keyType, algorithm)
	}
	return as.SignWithAlgorithm(rand.Reader, data, algorithm)
}
