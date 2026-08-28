package providers

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/urfave/cli/v3"
)

var registryMu sync.RWMutex
var registry = make([]*Registration, 0)

func Register(registration Registration) {
	// normalize the registration
	registration.Name = strings.ToLower(registration.Name)
	registryMu.Lock()
	defer registryMu.Unlock()
	for _, reg := range registry {
		if strings.EqualFold(reg.Name, registration.Name) {
			panic(fmt.Errorf("provider name '%s' already exists", registration.Name))
		}
	}
	registry = append(registry, &registration)
}

func AllFlags() []cli.Flag {
	var flags = make([]cli.Flag, 0)
	registryMu.RLock()
	defer registryMu.RUnlock()
	for _, reg := range registry {
		flags = append(flags, reg.Flags...)
	}
	return flags
}

func AllProviderNames() []string {
	registryMu.RLock()
	var names = make([]string, len(registry))
	defer registryMu.RUnlock()
	for i, reg := range registry {
		names[i] = strings.ToLower(reg.Name)
	}
	return names
}

func getRegistration(name string) *Registration {
	registryMu.RLock()
	defer registryMu.RUnlock()
	for _, reg := range registry {
		if strings.EqualFold(reg.Name, name) {
			return reg
		}
	}
	return nil
}

func GetProvider(cmd *cli.Command) (Provider, error) {
	provider := strings.TrimSpace(cmd.String("provider"))
	if provider == "" {
		return nil, fmt.Errorf("--provider is required")
	}

	reg := getRegistration(provider)
	if reg == nil {
		return nil, fmt.Errorf("no provider found named '%s'", provider)
	}

	return reg.Prepare(cmd)
}

type Provider func(ctx context.Context) (Backend, error)

type Registration struct {
	Name    string
	Flags   []cli.Flag
	Prepare func(cmd *cli.Command) (Provider, error)
}
