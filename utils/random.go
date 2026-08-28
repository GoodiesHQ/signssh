package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func RandomID() (string, error) {
	var b [16]byte

	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate random ID: %w", err)
	}

	return hex.EncodeToString(b[:]), nil
}
