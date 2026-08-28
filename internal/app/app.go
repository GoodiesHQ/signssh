package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/goodieshq/signssh/internal/config"
	"github.com/goodieshq/signssh/internal/conn"
	_ "github.com/goodieshq/signssh/internal/providers/azurekv"
	_ "github.com/goodieshq/signssh/internal/providers/local"
	"github.com/goodieshq/signssh/pkg/providers"
	"github.com/urfave/cli/v3"
)

func Run(ctx context.Context, args []string) int {
	signals := []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}
	ctx, stop := signal.NotifyContext(ctx, signals...)
	defer stop()

	go func() {
		<-ctx.Done()
		stop()
	}()

	_, err := exec.LookPath("ssh")
	if err != nil {
		fmt.Fprintln(os.Stderr, "OpenSSH client 'ssh' not found")
		return 1
	}

	cmd := &cli.Command{
		Name:    config.AppName,
		Version: config.AppVersion,
		Usage:   "SSH wrapper using a signing provider as a private key",
		UsageText: "signssh [options] <key-name> [user@]<hostname[:port]>" +
			"\n" + "signssh [options] --list",
		Flags:          allFlags(),
		ExitErrHandler: func(context.Context, *cli.Command, error) {},
		Action:         run,
	}

	err = cmd.Run(ctx, args)
	if err == nil {
		return 0
	}

	if ctx.Err() != nil {
		return 130
	}

	// ssh child process completed and retured non-zero
	var execErr *exec.ExitError
	if errors.As(err, &execErr) {
		return execErr.ExitCode()
	}

	// print any cli.Exit(...) error from arg validation/provider setup
	var exitCoder cli.ExitCoder
	if errors.As(err, &exitCoder) {
		if msg := exitCoder.Error(); msg != "" {
			fmt.Fprintln(os.Stderr, msg)
		}
		return exitCoder.ExitCode()
	}

	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	return 1
}

func run(ctx context.Context, cmd *cli.Command) error {
	cfg, provider, err := config.FromCmd(cmd)
	if err != nil {
		return err
	}

	// if the --list flag is set, list available keys and exit
	if cmd.Bool("list") {
		if cmd.NArg() != 0 {
			return exitErr("--list does not accept positional arguments")
		}

		return runList(ctx, cfg, provider)
	}

	// if the --public flag is set, only the key name must be set
	if cmd.Bool("public") {
		if cmd.NArg() != 1 {
			return exitErr("--public requires only the name of the key")
		}
		keyName := strings.ToLower(strings.TrimSpace(cmd.Args().Get(0)))
		return runPublic(ctx, cfg, provider, keyName)
	}

	// now we can assume the desire is to run a new connection
	if cmd.NArg() != 2 {
		return exitErr("expecting <key-name> [user@]<hostname[:port]>")
	}

	keyName := strings.ToLower(strings.TrimSpace(cmd.Args().Get(0)))
	keyNameFull := cfg.Prefix + keyName
	target := cmd.Args().Get(1)

	dest, err := conn.ParseDestination(target)
	if err != nil {
		return exitErr(err)
	}

	if dest.User == "" {
		dest.User = cfg.Username
	}

	return runConnect(ctx, keyNameFull, dest, provider, cfg.Debug)
}

func allFlags() []cli.Flag {
	return slices.Concat(flagsDefault, providers.AllFlags())
}

var flagsDefault = []cli.Flag{
	&cli.StringFlag{
		Name:    "provider",
		Usage:   "Signing provider",
		Sources: cli.EnvVars("SIGNSSH_PROVIDER"),
	},
	&cli.StringFlag{
		Name:    "prefix",
		Usage:   "Key name prefix to filter keys",
		Sources: cli.EnvVars("SIGNSSH_PREFIX"),
	},
	&cli.StringFlag{
		Name:    "username",
		Aliases: []string{"u"},
		Usage:   "SSH username",
		Sources: cli.EnvVars("SIGNSSH_USERNAME"),
	},
	&cli.BoolFlag{
		Name:    "list",
		Aliases: []string{"l"},
		Usage:   "List all available keys from the provider",
	},
	&cli.BoolFlag{
		Name:    "public",
		Aliases: []string{"p"},
		Usage:   "Print the OpenSSH public key for <key-name> and exit",
	},
	&cli.BoolFlag{
		Name:    "logout",
		Usage:   "Log out and destroy the current session",
		Sources: cli.EnvVars("SIGNSSH_LOGOUT"),
	},
	&cli.BoolFlag{
		Name:    "debug",
		Aliases: []string{"v"},
		Usage:   "Enable debug output",
		Sources: cli.EnvVars("SIGNSSH_DEBUG"),
	},
}

// exitErr wraps an error as a CLI exit with a standard status code
func exitErr(err any) error {
	if err, ok := err.(error); ok {
		return cli.Exit(err.Error(), 2)
	}
	if err, ok := err.(string); ok {
		return cli.Exit(err, 2)
	}
	return cli.Exit(fmt.Sprintf("%+v", err), 2)
}
