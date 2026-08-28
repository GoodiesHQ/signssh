package azurekv

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/goodieshq/signssh/pkg/providers"
	"github.com/urfave/cli/v3"
)

func init() {
	providers.Register(register())
}

// Name is the --provider value for this provider.
const Name = "azure-key-vault"

// defaultClientID is the Microsoft Azure CLI public client ID.
const defaultClientID = "1950a258-227b-4e31-a9cf-717495945fc2"

func register() providers.Registration {
	return providers.Registration{
		Name:  Name,
		Flags: flags(),
		Prepare: func(cmd *cli.Command) (providers.Provider, error) {
			// Validate the required values
			tenantID := strings.TrimSpace(cmd.String("azure-tenant-id"))
			clientID := strings.TrimSpace(cmd.String("azure-client-id"))
			keyVault := strings.TrimSpace(cmd.String("azure-key-vault"))
			environment := strings.TrimSpace(cmd.String("azure-environment"))

			if tenantID == "" {
				return nil, errors.New("--azure-tenant-id is required")
			}
			if clientID == "" {
				return nil, errors.New("--azure-client-id is required")
			}
			if keyVault == "" {
				return nil, errors.New("--azure-key-vault is required")
			}

			env, err := getEnvironmentFromName(environment, keyVault)
			if err != nil {
				return nil, fmt.Errorf("invalid environment: %w", err)
			}

			return func(ctx context.Context) (providers.Backend, error) {
				vault, err := New(ctx, tenantID, clientID, env)
				if err != nil {
					return nil, err
				}
				return vault, nil
			}, nil
		},
	}
}

func flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "azure-tenant-id",
			Usage:   "Microsoft Entra tenant ID",
			Sources: cli.EnvVars("SIGNSSH_AZURE_TENANT_ID"),
		},
		&cli.StringFlag{
			Name:    "azure-client-id",
			Usage:   "Microsoft Entra application/client ID",
			Value:   defaultClientID,
			Sources: cli.EnvVars("SIGNSSH_AZURE_CLIENT_ID"),
		},
		&cli.StringFlag{
			Name:    "azure-key-vault",
			Usage:   "Azure Key Vault name",
			Sources: cli.EnvVars("SIGNSSH_AZURE_KEY_VAULT"),
		},
		&cli.StringFlag{
			Name:    "azure-environment",
			Value:   "global",
			Sources: cli.EnvVars("SIGNSSH_AZURE_ENVIRONMENT"),
		},
	}
}
