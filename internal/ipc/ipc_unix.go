//go:build linux || darwin

package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/goodieshq/signssh/internal/config"
)

// implementation of IPC for Linux and macOS
func newIPC() (*IPC, error) {
	// create a temporary directory for the SSH agent socket
	dir, err := os.MkdirTemp("", config.AppName+"-agent-*")
	if err != nil {
		return nil, fmt.Errorf("create SSH agent directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("secure SSH agent directory: %w", err)
	}

	// create the SSH agent socket
	socketPath := filepath.Join(dir, "agent.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("create SSH agent socket: %w", err)
	}

	return &IPC{
		Listener: listener,
		Endpoint: socketPath,
		Cleanup: func() error {
			listener.Close()
			return os.RemoveAll(dir)
		},
	}, nil
}
