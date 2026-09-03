package local

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/goodieshq/signssh/pkg/providers"
	"golang.org/x/crypto/ssh"
)

// defaultKeyNames are the ~/.ssh files probed when no --local-key-path is
// given. Each file's basename becomes its key name.
var defaultKeyNames = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

// Local is a Backend over one or more on-disk OpenSSH private keys. Each key is
// addressed by its file's basename ("id_rsa", "id_ed25519", ...). A
// --local-key-path adds its own basename, overriding a same-named default.
type Local struct {
	keys     map[string]string // key name -> file path
	password string            // passphrase for whichever key is opened
}

// New discovers the default ~/.ssh keys that exist, plus an optional explicit
// path. It fails only when nothing is found.
func New(extraPath, password string) (*Local, error) {
	keys := map[string]string{}

	if home, err := os.UserHomeDir(); err == nil {
		for _, name := range defaultKeyNames {
			p := filepath.Join(home, ".ssh", name)
			if fileExists(p) {
				keys[name] = p
			}
		}
	}

	if extraPath != "" {
		p := extraPath
		if abs, err := filepath.Abs(extraPath); err == nil {
			p = abs
		}
		if !fileExists(p) {
			return nil, fmt.Errorf("local: key file %q not found", extraPath)
		}
		keys[filepath.Base(p)] = p
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("local: no keys found; put one of %v in ~/.ssh or pass --local-key-path", defaultKeyNames)
	}

	return &Local{keys: keys, password: password}, nil
}

// ListKeyNames returns the discovered key names, sorted. The prefix argument is
// ignored: local key names are filenames, not a namespace.
func (l *Local) ListKeyNames(_ context.Context, _ string) ([]string, error) {
	return slices.Sorted(maps.Keys(l.keys)), nil
}

func (l *Local) GetPublicKey(_ context.Context, name string) (ssh.PublicKey, error) {
	path, err := l.resolve(name)
	if err != nil {
		return nil, err
	}

	// Prefer the ".pub" sidecar so an encrypted key needs no passphrase here.
	if pub, err := readPublicKeyFile(path + ".pub"); err == nil {
		return pub, nil
	}

	signer, err := readPrivateKey(path, l.password)
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(signer.Public())
}

func (l *Local) OpenSigner(_ context.Context, name string) (providers.Signer, error) {
	path, err := l.resolve(name)
	if err != nil {
		return nil, err
	}
	signer, err := readPrivateKey(path, l.password)
	if err != nil {
		return nil, err
	}
	return providers.FromCryptoSigner(name, signer)
}

func (l *Local) resolve(name string) (string, error) {
	if path, ok := l.keys[name]; ok {
		return path, nil
	}
	return "", fmt.Errorf("local: unknown key %q (available: %s)",
		name, strings.Join(slices.Sorted(maps.Keys(l.keys)), ", "))
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func readPublicKeyFile(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	return pub, err
}
