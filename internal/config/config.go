package config

import (
	"strings"

	"github.com/urfave/cli/v3"
)

// Config holds the action-level options shared by every provider subcommand.
type Config struct {
	Prefix   string
	Username string
	Debug    bool
}

// FromCmd reads the common flags off a provider subcommand (--debug is a
// persistent root flag; --prefix and --username are local to the subcommand).
func FromCmd(cmd *cli.Command) *Config {
	return &Config{
		Prefix:   strings.TrimSpace(cmd.String("prefix")),
		Username: strings.TrimSpace(cmd.String("username")),
		Debug:    cmd.Bool("debug"),
	}
}
