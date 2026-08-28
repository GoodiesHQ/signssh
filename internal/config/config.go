package config

import (
	"fmt"
	"strings"

	"github.com/goodieshq/signssh/pkg/providers"
	"github.com/urfave/cli/v3"
)

// signssh config
type Config struct {
	Provider string
	Prefix   string
	Username string
	Debug    bool
}

func FromCmd(cmd *cli.Command) (*Config, providers.Provider, error) {
	cfg := Config{
		Provider: strings.TrimSpace(cmd.String("provider")),
		Prefix:   strings.TrimSpace(cmd.String("prefix")),
		Username: strings.TrimSpace(cmd.String("username")),
		Debug:    cmd.Bool("debug"),
	}

	if cfg.Provider == "" {
		valid := strings.Join(providers.AllProviderNames(), ", ")
		return nil, nil, fmt.Errorf("--provider must be provided (%s)", valid)
	}

	provider, err := providers.GetProvider(cmd)
	if err != nil {
		return nil, nil, err
	}

	return &cfg, provider, nil
}
