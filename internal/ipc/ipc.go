package ipc

import (
	"net"
)

type IPC struct {
	Listener net.Listener
	Endpoint string
	Cleanup  func() error
}

func New() (*IPC, error) {
	return newIPC()
}
