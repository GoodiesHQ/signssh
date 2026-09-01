package azurekv

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/goodieshq/signssh/pkg/providers"
	"golang.org/x/crypto/ssh"
)

type KeyVault struct {
	keys  *azkeys.Client
	scope string
}

// New creates a new KeyVault that can retrieve private keys from Azure Key Vault
func New(ctx context.Context, tenantID, clientID string, env *environment) (*KeyVault, error) {
	cred, err := newCredential(ctx, tenantID, clientID, env.scope)
	if err != nil {
		return nil, fmt.Errorf("authenticate to Microsoft Entra ID: %w", err)
	}

	keyClient, err := azkeys.NewClient(env.url, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("create Azure Key Vault client: %w", err)
	}

	return &KeyVault{
		keys: keyClient,
	}, nil
}

func (kv *KeyVault) GetPublicKey(ctx context.Context, keyName string) (ssh.PublicKey, error) {
	resp, err := kv.keys.GetKey(ctx, keyName, "", &azkeys.GetKeyOptions{})
	if err != nil {
		return nil, fmt.Errorf("get Key Vault key: %w", err)
	}

	if resp.Key == nil || resp.Key.Kty == nil {
		return nil, fmt.Errorf("key %s has no public key", keyName)
	}

	var pubKey any
	switch *resp.Key.Kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		pubKey, err = jwkToRSA(resp.Key, keyName)
	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		pubKey, err = jwkToECDSA(resp.Key, keyName)
	default:
		return nil, fmt.Errorf("key %s uses unsupported type %s", keyName, string(*resp.Key.Kty))
	}
	if err != nil {
		return nil, err
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("convert %s key to SSH public key: %w", keyName, err)
	}

	return sshPubKey, nil
}

func (kv *KeyVault) ListKeyNames(ctx context.Context, prefix string) ([]string, error) {
	pager := kv.keys.NewListKeyPropertiesPager(nil)
	var names []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list Key Vault keys: %w", err)
		}

		for _, key := range page.Value {
			// skip keys that don't have a KID or a name
			if key == nil || key.KID == nil {
				continue
			}

			name := key.KID.Name()
			if name == "" {
				continue
			}

			// a prefix is optional, filter out keys that don't match the prefix
			if prefix != "" {
				if !strings.HasPrefix(name, prefix) {
					continue
				}
				name = strings.TrimPrefix(name, prefix)
			}
			if name != "" {
				names = append(names, name)
			}
		}
	}
	return names, nil
}

func (kv *KeyVault) OpenSigner(ctx context.Context, keyName string) (providers.Signer, error) {
	pubKey, err := kv.GetPublicKey(ctx, keyName)
	if err != nil {
		return nil, err
	}

	return &signerKeyVault{
		keys:    kv.keys,
		keyName: keyName,
		pubKey:  pubKey,
	}, nil
}

type signerKeyVault struct {
	keys    *azkeys.Client
	keyName string
	pubKey  ssh.PublicKey
}

func (sig *signerKeyVault) Name() string {
	return sig.keyName
}

func (sig *signerKeyVault) PublicKey() ssh.PublicKey {
	return sig.pubKey
}

func (sig *signerKeyVault) Algorithms() []string {
	return providers.AlgorithmsFor(sig.pubKey.Type())
}

func (sig *signerKeyVault) Sign(ctx context.Context, algorithm string, data []byte) (*ssh.Signature, error) {
	azAlg, digest, isECDSA, err := azureSignParams(algorithm, data)
	if err != nil {
		return nil, err
	}

	resp, err := sig.keys.Sign(ctx, sig.keyName, "", azkeys.SignParameters{
		Algorithm: &azAlg,
		Value:     digest,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azure key vault sign: %w", err)
	}

	blob := resp.Result
	if isECDSA {
		// Key Vault returns the ECDSA signature IEEE P1363
		blob, err = ecdsaP1363ToSSHBlob(resp.Result)
		if err != nil {
			return nil, err
		}
	}

	return &ssh.Signature{Format: algorithm, Blob: blob}, nil
}

// azureSignParams maps an SSH signature algorithm to the Key Vault algorithm and digest
func azureSignParams(algorithm string, data []byte) (alg azkeys.SignatureAlgorithm, digest []byte, isECDSA bool, err error) {
	switch algorithm {
	case ssh.KeyAlgoRSASHA256:
		h := sha256.Sum256(data)
		return azkeys.SignatureAlgorithmRS256, h[:], false, nil
	case ssh.KeyAlgoRSASHA512:
		h := sha512.Sum512(data)
		return azkeys.SignatureAlgorithmRS512, h[:], false, nil
	case ssh.KeyAlgoECDSA256:
		h := sha256.Sum256(data)
		return azkeys.SignatureAlgorithmES256, h[:], true, nil
	case ssh.KeyAlgoECDSA384:
		h := sha512.Sum384(data)
		return azkeys.SignatureAlgorithmES384, h[:], true, nil
	case ssh.KeyAlgoECDSA521:
		h := sha512.Sum512(data)
		return azkeys.SignatureAlgorithmES512, h[:], true, nil
	default:
		return "", nil, false, fmt.Errorf("azure key vault: unsupported signature algorithm %q", algorithm)
	}
}
