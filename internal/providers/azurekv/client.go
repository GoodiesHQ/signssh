package azurekv

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/goodieshq/signssh/pkg/providers"
	"github.com/goodieshq/signssh/utils"
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

	publicKey, err := utils.JwkToRSA(resp.Key, keyName)
	if err != nil {
		return nil, fmt.Errorf("convert JWK to RSA: %w", err)
	}

	sshPubKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("convert RSA to SSH public key: %w", err)
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

func (sig *signerKeyVault) Sign(ctx context.Context, alg providers.Algorithm, data []byte) ([]byte, error) {
	algAz, err := azureAlg(alg)
	if err != nil {
		return nil, err
	}

	resp, err := sig.keys.Sign(ctx, sig.keyName, "", azkeys.SignParameters{
		Algorithm: &algAz,
		Value:     data,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("sign data: %w", err)
	}

	return resp.Result, nil
}

func azureAlg(alg providers.Algorithm) (azkeys.SignatureAlgorithm, error) {
	switch alg {
	case providers.RSA256:
		return azkeys.SignatureAlgorithmRS256, nil
	case providers.RSA512:
		return azkeys.SignatureAlgorithmRS512, nil
	}
	return "", fmt.Errorf("unsupported signing algorithm")
}
