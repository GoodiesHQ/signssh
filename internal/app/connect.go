package app

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/goodieshq/signssh/internal/conn"
	"github.com/goodieshq/signssh/internal/ipc"
	"github.com/goodieshq/signssh/internal/sshagent"
	"github.com/goodieshq/signssh/pkg/providers"
)

func runConnect(ctx context.Context, keyName string, dest *conn.Destination, provider providers.Provider, debug bool, sshArgs []string) error {
	ctxTimed, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	backend, err := provider(ctxTimed)
	if err != nil {
		return exitErr(err)
	}

	signer, err := backend.OpenSigner(ctxTimed, keyName)
	if err != nil {
		return exitErr(err)
	}

	agentIPC, err := ipc.New()
	if err != nil {
		return exitErr(err)
	}
	defer agentIPC.Cleanup()

	agentCtx, cancelAgent := context.WithCancel(ctx)
	defer cancelAgent()

	agt := sshagent.NewAgent(agentCtx, signer)

	go func() {
		if err := agt.Serve(agentCtx, agentIPC.Listener); err != nil {
			fmt.Fprintf(os.Stderr, "SSH agent error: %v\n", err)
		}
	}()

	// Return the ssh error unwrapped so Run can mirror ssh's exit status.
	return sshagent.RunSSH(
		agentCtx,
		agentIPC.Endpoint,
		dest,
		debug,
		sshArgs,
	)
}
