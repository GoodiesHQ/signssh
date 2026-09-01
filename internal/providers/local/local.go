package local

import (
	"context"
	"crypto"
	"fmt"

	"github.com/goodieshq/signssh/pkg/providers"
	"golang.org/x/crypto/ssh"
)

// keyName is the only key name this provider serves.
const keyName = "local"

// Local is a Backend backed by a single in-process private key loaded from an
// OpenSSH key file. RSA, ECDSA (P-256/384/521) and Ed25519 keys are supported.
type Local struct {
	key crypto.Signer
	pub ssh.PublicKey
}

// New wraps an already-parsed private key.
func New(key crypto.Signer) (*Local, error) {
	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("derive SSH public key: %w", err)
	}
	return &Local{key: key, pub: pub}, nil
}

func (l *Local) ListKeyNames(context.Context, string) ([]string, error) {
	return []string{keyName}, nil
}

func (l *Local) GetPublicKey(_ context.Context, name string) (ssh.PublicKey, error) {
	if name != keyName {
		return nil, fmt.Errorf("local provider only serves the key named %q", keyName)
	}
	return l.pub, nil
}

func (l *Local) OpenSigner(ctx context.Context, name string) (providers.Signer, error) {
	if _, err := l.GetPublicKey(ctx, name); err != nil {
		return nil, err
	}
	return providers.FromCryptoSigner(keyName, l.key)
}
