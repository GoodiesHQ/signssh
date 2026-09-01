package local

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goodieshq/signssh/pkg/providers"
	"github.com/urfave/cli/v3"
	"golang.org/x/crypto/ssh"
)

var defaultKeyNames = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

func init() {
	providers.Register(register())
}

// Name is the --provider value for this provider.
const Name = "local"

func register() providers.Registration {
	return providers.Registration{
		Name:  Name,
		Flags: flags(),
		Prepare: func(cmd *cli.Command) (providers.Provider, error) {
			path := cmd.String("local-key-path")
			password := cmd.String("local-key-password")

			if path == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return nil, fmt.Errorf("unable to get home dir: %w", err)
				}

				for _, name := range defaultKeyNames {
					candidate := filepath.Join(home, ".ssh", name)
					if _, err := os.Stat(candidate); err == nil {
						path = candidate
						break
					}
				}
				if path == "" {
					return nil, fmt.Errorf("no default key found in ~/.ssh (%v); set --local-key-path", defaultKeyNames)
				}
			}

			return func(ctx context.Context) (providers.Backend, error) {
				privateKey, err := readPrivateKey(path, password)
				if err != nil {
					return nil, err
				}

				return New(privateKey)
			}, nil
		},
	}
}

func readPrivateKey(filename string, password string) (crypto.Signer, error) {
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
		return nil, fmt.Errorf("local provider: unsupported key type %T (want RSA, ECDSA, or Ed25519)", key)
	}

	return signer, nil
}

func flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "local-key-path",
			Usage:   "A local file path containing an OpenSSH private key",
			Sources: cli.EnvVars("SIGNSSH_LOCAL_KEY_PATH"),
		},
		&cli.StringFlag{
			Name:    "local-key-password",
			Usage:   "The password for the OpenSSH private key",
			Sources: cli.EnvVars("SIGNSSH_LOCAL_KEY_PASSWORD"),
		},
	}
}
