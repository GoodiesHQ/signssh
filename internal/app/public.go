package app

import (
	"context"
	"fmt"

	"github.com/goodieshq/signssh/internal/config"
	"github.com/goodieshq/signssh/pkg/providers"
	"github.com/goodieshq/signssh/utils"
)

func runPublic(ctx context.Context, cfg *config.Config, provider providers.Provider, keyName string) error {
	backend, err := provider(ctx)
	if err != nil {
		return exitErr(err)
	}

	key, err := backend.GetPublicKey(ctx, cfg.Prefix+keyName)
	if err != nil {
		return exitErr(err)
	}

	fmt.Print(utils.ToOpenSSH(key))
	return nil
}
