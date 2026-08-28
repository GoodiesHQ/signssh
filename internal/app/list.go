package app

import (
	"context"
	"fmt"

	"github.com/goodieshq/signssh/internal/config"
	"github.com/goodieshq/signssh/pkg/providers"
)

func runList(ctx context.Context, cfg *config.Config, provider providers.Provider) error {
	backend, err := provider(ctx)
	if err != nil {
		return exitErr(err)
	}

	keyNames, err := backend.ListKeyNames(ctx, cfg.Prefix)
	if err != nil {
		return exitErr(err)
	}

	for _, keyName := range keyNames {
		fmt.Println(keyName)
	}

	return nil
}
