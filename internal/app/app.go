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

	if _, err := exec.LookPath("ssh"); err != nil {
		fmt.Fprintln(os.Stderr, "OpenSSH client 'ssh' not found")
		return 1
	}

	// Everything after a lone "--" is handed verbatim to the ssh child.
	cliArgs, sshExtra := splitPassthrough(args)

	root := &cli.Command{
		Name:    config.AppName,
		Version: config.AppVersion,
		Usage:   "SSH using a signing provider as your private key",
		UsageText: strings.Join([]string{
			"signssh <provider> [options] <key-name> [user@]<host>[:port] [-- <ssh args>]",
			"signssh <provider> --list",
			"signssh <provider> --public <key-name>",
		}, "\n"),
		Flags:          rootFlags,
		Commands:       providerCommands(sshExtra),
		ExitErrHandler: func(context.Context, *cli.Command, error) {},
		Action: func(_ context.Context, cmd *cli.Command) error {
			// reached when the first argument was not a known provider
			if cmd.Args().Present() {
				return exitErr(fmt.Sprintf("unknown provider %q; run 'signssh --help' for the list", cmd.Args().First()))
			}
			return cli.ShowAppHelp(cmd)
		},
	}

	// SIGNSSH_PROVIDER selects the provider subcommand when the user does not
	// type one, so an operator can push hidden env and employees just run
	// `signssh [<key>] [user@]<host>`. An explicit subcommand still wins.
	if envProvider := strings.ToLower(strings.TrimSpace(os.Getenv("SIGNSSH_PROVIDER"))); envProvider != "" {
		if !knownProvider(envProvider) {
			fmt.Fprintf(os.Stderr, "SIGNSSH_PROVIDER=%q is not a registered provider\n", envProvider)
			return 2
		}
		root.DefaultCommand = envProvider
	}

	err := root.Run(ctx, cliArgs)
	if err == nil {
		return 0
	}

	// interrupted by a signal
	if ctx.Err() != nil {
		return 130
	}

	// the ssh child ran and exited non-zero: mirror its status, stay quiet
	var execErr *exec.ExitError
	if errors.As(err, &execErr) {
		return execErr.ExitCode()
	}

	// a cli.Exit(...) from arg validation / provider setup
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

// rootFlags live on the root command. urfave/cli v3 flags are persistent by
// default, so these are inherited by every provider subcommand and shown
// under GLOBAL OPTIONS.
var rootFlags = []cli.Flag{
	&cli.BoolFlag{
		Name:    "debug",
		Aliases: []string{"v"},
		Usage:   "Enable debug output",
		Sources: cli.EnvVars("SIGNSSH_DEBUG"),
	},
}

// commonActionFlags are added to every provider subcommand alongside its own
// provider flags.
func commonActionFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "prefix",
			Usage:   "Prepended to <key-name> and stripped from --list output",
			Sources: cli.EnvVars("SIGNSSH_PREFIX"),
		},
		&cli.StringFlag{
			Name:    "username",
			Aliases: []string{"u"},
			Usage:   "SSH username (a user@ in the destination wins)",
			Sources: cli.EnvVars("SIGNSSH_USERNAME"),
		},
		&cli.StringFlag{
			Name:    "key",
			Aliases: []string{"k"},
			Usage:   "Key name to use when it is not given as an argument",
			Sources: cli.EnvVars("SIGNSSH_KEY"),
		},
		&cli.BoolFlag{
			Name:    "list",
			Aliases: []string{"l"},
			Usage:   "List available keys and exit",
		},
		&cli.BoolFlag{
			Name:    "public",
			Aliases: []string{"p"},
			Usage:   "Print the OpenSSH public key for <key-name> and exit",
		},
	}
}

func knownProvider(name string) bool {
	for _, reg := range providers.All() {
		if reg.Name == name {
			return true
		}
	}
	return false
}

func splitPassthrough(args []string) (head, tail []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func providerCommands(sshExtra []string) []*cli.Command {
	regs := providers.All()
	cmds := make([]*cli.Command, 0, len(regs))
	for _, reg := range regs {
		cmds = append(cmds, providerCommand(reg, sshExtra))
	}
	return cmds
}

func providerCommand(reg providers.Registration, sshExtra []string) *cli.Command {
	return &cli.Command{
		Name:  reg.Name,
		Usage: reg.Usage,
		UsageText: strings.Join([]string{
			fmt.Sprintf("signssh %s [options] <key-name> [user@]<host>[:port] [-- <ssh args>]", reg.Name),
			fmt.Sprintf("signssh %s --list", reg.Name),
			fmt.Sprintf("signssh %s --public <key-name>", reg.Name),
		}, "\n"),
		Flags: slices.Concat(slices.Clone(reg.Flags), commonActionFlags()),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runProvider(ctx, cmd, reg, sshExtra)
		},
	}
}

func runProvider(ctx context.Context, cmd *cli.Command, reg providers.Registration, sshExtra []string) error {
	cfg := config.FromCmd(cmd)

	provider, err := reg.Prepare(cmd)
	if err != nil {
		return exitErr(err)
	}

	posArgs := cmd.Args().Slice()

	// A key name may come from a positional arg or, when it is not typed, from
	// --key / $SIGNSSH_KEY.
	flagKey := normalizeArg(cmd.String("key"))

	switch {
	case cmd.Bool("list"):
		if len(posArgs) != 0 {
			return exitErr("--list does not take arguments")
		}
		return runList(ctx, cfg, provider)

	case cmd.Bool("public"):
		key := flagKey
		switch len(posArgs) {
		case 0:
			if key == "" {
				return exitErr("--public needs a key: pass <key-name> or set SIGNSSH_KEY")
			}
		case 1:
			key = normalizeArg(posArgs[0])
		default:
			return exitErr("--public takes at most one <key-name>")
		}
		return runPublic(ctx, cfg, provider, key)
	}

	// connect
	var key, target string
	switch len(posArgs) {
	case 0:
		return cli.ShowSubcommandHelp(cmd)
	case 1:
		if flagKey == "" {
			return exitErr("missing destination: give <key-name> [user@]<host>[:port], or set SIGNSSH_KEY and pass just [user@]<host>[:port]")
		}
		key, target = flagKey, posArgs[0]
	case 2:
		key, target = normalizeArg(posArgs[0]), posArgs[1]
	default:
		return exitErr("too many arguments; expected <key-name> [user@]<host>[:port]")
	}

	dest, err := conn.ParseDestination(target)
	if err != nil {
		return exitErr(err)
	}
	if dest.User == "" {
		dest.User = cfg.Username
	}

	// ssh options: "-- <args>" from the command line first, then $SIGNSSH_SSH_ARGS.
	sshArgs := append(slices.Clone(sshExtra), strings.Fields(os.Getenv("SIGNSSH_SSH_ARGS"))...)

	return runConnect(ctx, cfg.Prefix+key, dest, provider, cfg.Debug, sshArgs)
}

func normalizeArg(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// exitErr wraps an error or message as a CLI exit with a standard status code.
func exitErr(err any) error {
	switch v := err.(type) {
	case error:
		return cli.Exit(v.Error(), 2)
	case string:
		return cli.Exit(v, 2)
	default:
		return cli.Exit(fmt.Sprintf("%+v", v), 2)
	}
}
