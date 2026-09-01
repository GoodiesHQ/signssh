package sshagent

import (
	"bytes"
	"context"
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
	return a.SignWithFlags(key, data, 0)
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

	alg, err := a.algorithm(flags)
	if err != nil {
		return nil, err
	}

	// The signer receives the raw challenge and returns a wire-ready
	// signature; all hashing and encoding happen there.
	sig, err := a.signer.Sign(a.ctx, alg, data)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	return sig, nil
}

// algorithm resolves the SSH signature algorithm to request from the signer.
// For RSA keys it honors the client's rsa-sha2 flags and refuses SHA-1; for
// ECDSA and Ed25519 keys there is exactly one algorithm and flags are ignored.
func (a *Agent) algorithm(flags agent.SignatureFlags) (string, error) {
	keyType := a.signer.PublicKey().Type()
	if keyType != ssh.KeyAlgoRSA {
		return keyType, nil
	}

	switch {
	case flags&agent.SignatureFlagRsaSha512 != 0:
		return ssh.KeyAlgoRSASHA512, nil
	case flags&agent.SignatureFlagRsaSha256 != 0:
		return ssh.KeyAlgoRSASHA256, nil
	default:
		return "", errors.New("RSA SHA-1 signatures are not supported; the server must offer rsa-sha2-256 or rsa-sha2-512")
	}
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
