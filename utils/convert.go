package utils

import (
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"golang.org/x/crypto/ssh"
)

func JwkToRSA(key *azkeys.JSONWebKey, keyName string) (*rsa.PublicKey, error) {
	switch *key.Kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		// supported
	default:
		return nil, fmt.Errorf("key %s type is %s, not RSA", keyName, strings.ToUpper(string(*key.Kty)))
	}

	if len(key.N) == 0 || len(key.E) == 0 {
		return nil, fmt.Errorf("key %s is missing modulus or exponent", keyName)
	}
	bigN := new(big.Int).SetBytes(key.N)
	bigE := new(big.Int).SetBytes(key.E)
	if !bigE.IsInt64() {
		return nil, fmt.Errorf(
			"RSA key %q has unsupported public exponent",
			keyName,
		)
	}
	e64 := bigE.Int64()
	if e64 <= 1 {
		return nil, fmt.Errorf(
			"RSA key %q has invalid public exponent %d",
			keyName,
			e64,
		)
	}

	return &rsa.PublicKey{
		N: bigN,
		E: int(e64),
	}, nil
}

func ToOpenSSH(pubKey ssh.PublicKey) string {
	return string(ssh.MarshalAuthorizedKey(pubKey))
}
