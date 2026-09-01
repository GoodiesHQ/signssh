package utils

import (
	"golang.org/x/crypto/ssh"
)

func ToOpenSSH(pubKey ssh.PublicKey) string {
	return string(ssh.MarshalAuthorizedKey(pubKey))
}
