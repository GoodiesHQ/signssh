package providers

import (
	"context"

	"golang.org/x/crypto/ssh"
)

type Backend interface {
	ListKeyNames(ctx context.Context, prefix string) ([]string, error)
	GetPublicKey(ctx context.Context, keyName string) (ssh.PublicKey, error)
	OpenSigner(ctx context.Context, keyName string) (Signer, error)
}
