package providers

import (
	"context"

	"golang.org/x/crypto/ssh"
)

type Signer interface {
	Name() string
	PublicKey() ssh.PublicKey
	Sign(ctx context.Context, algorithm string, data []byte) (*ssh.Signature, error)
	Algorithms() []string
}

func AlgorithmsFor(keyType string) []string {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoED25519:
		return []string{keyType}
	default:
		return nil
	}
}
