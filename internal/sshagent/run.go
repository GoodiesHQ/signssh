package sshagent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/goodieshq/signssh/internal/conn"
)

// RunSSH launches the OpenSSH client against the ephemeral agent. extraArgs are
// user-supplied options (everything after a "--" on the signssh command line,
// plus $SIGNSSH_SSH_ARGS) inserted in ssh's option position. They cannot
// override signssh's own -o settings: ssh uses the first value it sees for each
// option.
func RunSSH(ctx context.Context, identityAgent string, dest *conn.Destination, debug bool, extraArgs []string) error {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("OpenSSH client not found: %w", err)
	}

	// set up the SSH command arguments
	var args []string
	if debug {
		args = append(args, "-vvv")
	}

	args = append(
		args,
		"-o", "ForwardAgent=no",
		"-o", "IdentitiesOnly=no",
		"-o", "IdentityAgent="+identityAgent, // path to IPC
		"-o", "IdentityFile=none",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
	)

	args = append(args, extraArgs...)

	if dest.Port == 0 {
		dest.Port = 22
	}

	if dest.Port != 22 {
		args = append(
			args,
			"-p",
			strconv.Itoa(int(dest.Port)),
		)
	}

	target := dest.Host
	if dest.User != "" {
		target = dest.User + "@" + target
	}
	args = append(args, "--", target)

	if debug {
		fmt.Println("Running SSH command:", sshPath, args)
	}
	cmd := exec.CommandContext(ctx, sshPath, args...)

	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.WaitDelay = 3 * time.Second
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh: %w", err)
	}

	return nil
}
