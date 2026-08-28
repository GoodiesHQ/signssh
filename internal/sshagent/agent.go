package sshagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"net"

	"github.com/goodieshq/signssh/pkg/providers"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var _ agent.Agent = (*Agent)(nil)
var _ agent.ExtendedAgent = (*Agent)(nil)

type Agent struct {
	ctx    context.Context
	signer providers.Signer
}

func NewAgent(ctx context.Context, signer providers.Signer) *Agent {
	return &Agent{
		ctx,
		signer,
	}
}

func (a *Agent) List() ([]*agent.Key, error) {
	return []*agent.Key{
		{
			Format:  a.signer.PublicKey().Type(),
			Blob:    a.signer.PublicKey().Marshal(),
			Comment: a.signer.Name(),
		},
	}, nil
}

func (a *Agent) matchesKey(key ssh.PublicKey) bool {
	return key != nil &&
		key.Type() == a.signer.PublicKey().Type() &&
		bytes.Equal(key.Marshal(), a.signer.PublicKey().Marshal())
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	// sign with a default functionality (this will fail if used)
	return nil, fmt.Errorf("server must accept rsa-sha2-256/512 signatures")
	// return a.SignWithFlags(key, data, 0)
}

func (a *Agent) Add(key agent.AddedKey) error {
	return fmt.Errorf("unsupported: Add")
}

func (a *Agent) Remove(key ssh.PublicKey) error {
	return fmt.Errorf("unsupported: Remove")
}

func (a *Agent) RemoveAll() error {
	return fmt.Errorf("unsupported: RemoveAll")
}

func (a *Agent) Lock(passphrase []byte) error {
	return fmt.Errorf("unsupported: Lock")
}

func (a *Agent) Unlock(passphrase []byte) error {
	return fmt.Errorf("unsupported: Unlock")
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	return nil, nil
}

func (a *Agent) SignWithFlags(
	key ssh.PublicKey,
	data []byte,
	flags agent.SignatureFlags,
) (*ssh.Signature, error) {
	if !a.matchesKey(key) {
		return nil, errors.New("requested key does not match agent key")
	}

	var (
		digest []byte
		alg    providers.Algorithm
		format string
	)

	switch {
	case flags&agent.SignatureFlagRsaSha256 != 0:
		sum := sha256.Sum256(data)
		digest = sum[:]
		alg = providers.RSA256
		format = ssh.KeyAlgoRSASHA256
	case flags&agent.SignatureFlagRsaSha512 != 0:
		sum := sha512.Sum512(data)
		digest = sum[:]
		alg = providers.RSA512
		format = ssh.KeyAlgoRSASHA512
	default:
		return nil, fmt.Errorf("unknown signature flags: %d", flags)
	}

	signature, err := a.signer.Sign(a.ctx, alg, digest)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return &ssh.Signature{
		Format: format,
		Blob:   signature,
	}, nil
}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, fmt.Errorf("unsupported SSH agent extension: %s", extensionType)
}

func (a *Agent) Serve(ctx context.Context, listener net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			return fmt.Errorf("accept SSH agent connection: %w", err)
		}

		go func(conn net.Conn) {
			defer conn.Close()
			_ = agent.ServeAgent(a, conn)
		}(conn)
	}
}
