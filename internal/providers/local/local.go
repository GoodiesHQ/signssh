package local

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/goodieshq/signssh/pkg/providers"
	"golang.org/x/crypto/ssh"
)

type Local struct {
	privateKey *rsa.PrivateKey
	publicKey  ssh.PublicKey
}

type localSigner struct {
	privateKey *rsa.PrivateKey
	publicKey  ssh.PublicKey
}

func (ls *localSigner) Name() string {
	return "local"
}

func (ls *localSigner) PublicKey() ssh.PublicKey {
	return ls.publicKey
}

func (ls *localSigner) Sign(ctx context.Context, alg providers.Algorithm, digest []byte) ([]byte, error) {
	var h crypto.Hash
	switch alg {
	case providers.RSA256:
		h = crypto.SHA256
	case providers.RSA512:
		h = crypto.SHA512
	default:
		return nil, fmt.Errorf("unsupported algorithm")
	}
	if len(digest) != h.Size() {
		return nil, fmt.Errorf("local: expected %d-byte digest, got %d", h.Size(), len(digest))
	}

	return rsa.SignPKCS1v15(rand.Reader, ls.privateKey, h, digest)
}

func (l *Local) GetPublicKey(_ context.Context, keyName string) (ssh.PublicKey, error) {
	if keyName != "local" {
		return nil, fmt.Errorf("invalid local key, must always use 'local'")
	}

	return l.publicKey, nil
}

func (l *Local) ListKeyNames(_ context.Context, _ string) ([]string, error) {
	return []string{"local"}, nil
}

func (l *Local) OpenSigner(ctx context.Context, keyName string) (providers.Signer, error) {
	_, err := l.GetPublicKey(ctx, keyName)
	if err != nil {
		return nil, err
	}

	return &localSigner{privateKey: l.privateKey, publicKey: l.publicKey}, nil
}

func New(privateKey *rsa.PrivateKey) (*Local, error) {
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Local{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}
