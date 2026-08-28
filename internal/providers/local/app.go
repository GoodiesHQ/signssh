package local

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goodieshq/signssh/pkg/providers"
	"github.com/urfave/cli/v3"
	"golang.org/x/crypto/ssh"
)

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

				path = filepath.Join(home, ".ssh", "id_rsa")
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

func readPrivateKey(filename string, password string) (*rsa.PrivateKey, error) {
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

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("local provider only supports RSA keys, got %T", key)
	}

	return rsaKey, nil
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
