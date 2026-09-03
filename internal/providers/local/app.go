package local

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"os"

	"github.com/goodieshq/signssh/pkg/providers"
	"github.com/urfave/cli/v3"
	"golang.org/x/crypto/ssh"
)

func init() {
	providers.Register(register())
}

// Name is this provider's subcommand name.
const Name = "local"

func register() providers.Registration {
	return providers.Registration{
		Name:  Name,
		Usage: "Sign with local OpenSSH private key files",
		Flags: flags(),
		Prepare: func(cmd *cli.Command) (providers.Provider, error) {
			path := cmd.String("local-key-path")
			password := cmd.String("local-key-password")

			return func(ctx context.Context) (providers.Backend, error) {
				return New(path, password)
			}, nil
		},
	}
}

func readPrivateKey(filename, password string) (crypto.Signer, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var key any
	if password == "" {
		key, err = ssh.ParseRawPrivateKey(data)
	} else {
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(password))
	}
	if err != nil {
		return nil, err
	}

	// ssh.ParseRawPrivateKey returns *ed25519.PrivateKey; crypto.Signer is
	// implemented by the value type.
	if p, ok := key.(*ed25519.PrivateKey); ok {
		key = *p
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("local: unsupported key type %T in %s (want RSA, ECDSA, or Ed25519)", key, filename)
	}

	return signer, nil
}

func flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "local-key-path",
			Usage:   "Path to an extra OpenSSH private key (listed by its filename)",
			Sources: cli.EnvVars("SIGNSSH_LOCAL_KEY_PATH"),
		},
		&cli.StringFlag{
			Name:    "local-key-password",
			Usage:   "Passphrase for the private key being used",
			Sources: cli.EnvVars("SIGNSSH_LOCAL_KEY_PASSWORD"),
		},
	}
}
