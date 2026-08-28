package providers

import (
	"context"

	"github.com/goodieshq/signssh/utils"
	"golang.org/x/crypto/ssh"
)

type Algorithm uint32

const (
	RSA256 Algorithm = iota
	RSA512
)

type Signer interface {
	Name() string
	PublicKey() ssh.PublicKey
	Sign(ctx context.Context, algorithm Algorithm, data []byte) ([]byte, error)
}

func SignerPublicKey(signer Signer) string {
	return utils.ToOpenSSH(signer.PublicKey())
}
