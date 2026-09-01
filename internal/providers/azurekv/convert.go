package azurekv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"golang.org/x/crypto/ssh"
)

// jwkToRSA converts the Azure-provided public key to *rsa.PublicKey
func jwkToRSA(key *azkeys.JSONWebKey, keyName string) (*rsa.PublicKey, error) {
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

// jwkToECDSA converts an Azure Key Vault EC public JWK to an *ecdsa.PublicKey.
// Only the NIST curves that SSH can use (P-256/P-384/P-521) are allowed.
func jwkToECDSA(key *azkeys.JSONWebKey, keyName string) (*ecdsa.PublicKey, error) {
	switch *key.Kty {
	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		// supported
	default:
		return nil, fmt.Errorf("key %s type is %s, not EC", keyName, strings.ToUpper(string(*key.Kty)))
	}

	if key.Crv == nil {
		return nil, fmt.Errorf("key %s has no curve name", keyName)
	}

	var curve elliptic.Curve
	switch *key.Crv {
	case azkeys.CurveNameP256:
		curve = elliptic.P256()
	case azkeys.CurveNameP384:
		curve = elliptic.P384()
	case azkeys.CurveNameP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("key %s uses unsupported curve %s", keyName, string(*key.Crv))
	}

	if len(key.X) == 0 || len(key.Y) == 0 {
		return nil, fmt.Errorf("key %s is missing the X or Y coordinate", keyName)
	}
	x := new(big.Int).SetBytes(key.X)
	y := new(big.Int).SetBytes(key.Y)
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("key %s public point is not on curve %s", keyName, string(*key.Crv))
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// ecdsaP1363ToSSHBlob converts a raw r||s ECDSA signature into an SSH ECDSA
func ecdsaP1363ToSSHBlob(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return nil, fmt.Errorf("azure key vault: malformed ECDSA signature (%d bytes)", len(raw))
	}
	n := len(raw) / 2
	return ssh.Marshal(struct {
		R, S *big.Int
	}{
		R: new(big.Int).SetBytes(raw[:n]),
		S: new(big.Int).SetBytes(raw[n:]),
	}), nil
}
