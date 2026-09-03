package providers

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/urfave/cli/v3"
)

var (
	registryMu sync.RWMutex
	registry   []Registration
)

// Register adds a provider. It is meant to be called from an init function and
// panics on a duplicate name.
func Register(registration Registration) {
	registration.Name = strings.ToLower(strings.TrimSpace(registration.Name))

	registryMu.Lock()
	defer registryMu.Unlock()
	for _, reg := range registry {
		if reg.Name == registration.Name {
			panic(fmt.Errorf("provider name %q already registered", registration.Name))
		}
	}
	registry = append(registry, registration)
}

// All returns every registered provider in registration order.
func All() []Registration {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return slices.Clone(registry)
}

// Provider is a lazily-constructed connection to a signing backend.
type Provider func(ctx context.Context) (Backend, error)

// Registration is what a provider package contributes to the CLI: a name (its
// subcommand), a one-line description, the flags it needs, and a hook that
// turns parsed flags into a Provider.
type Registration struct {
	Name    string
	Usage   string
	Flags   []cli.Flag
	Prepare func(cmd *cli.Command) (Provider, error)
}
