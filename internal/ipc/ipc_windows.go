//go:build windows

package ipc

import (
	"fmt"

	"github.com/Microsoft/go-winio"
	"github.com/goodieshq/signssh/internal/config"
	"github.com/goodieshq/signssh/utils"
)

func newIPC() (*IPC, error) {
	// generate a random ID for the named pipe
	id, err := utils.RandomID()
	if err != nil {
		return nil, err
	}

	// create the named pipe for the agent
	name := config.AppName + "-" + id
	pipeNameSys := `\\.\pipe\` + name
	pipeNameSSH := `//./pipe/` + name

	// Leaving SecurityDescriptor unset makes go-winio apply Windows' default
	// named pipe ACL (RtlDefaultNpAcl), which already restricts the pipe to
	// the creating user, Administrators, and LocalSystem.
	listener, err := winio.ListenPipe(
		pipeNameSys,
		&winio.PipeConfig{
			MessageMode: false,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create SSH agent named pipe: %w", err)
	}

	return &IPC{
		Listener: listener,
		Endpoint: pipeNameSSH,
		Cleanup: func() error {
			return listener.Close()
		},
	}, nil
}
