package azurekv

import (
	"fmt"
	"strings"
)

type environment struct {
	scope string
	url   string
}

var environmentTemplates = map[string]environment{
	"global": {
		scope: "https://vault.azure.net/.default",
		url:   "https://%s.vault.azure.net/",
	},
	"government": {
		scope: "https://vault.usgovcloudapi.net/.default",
		url:   "https://%s.vault.usgovcloudapi.net/",
	},
	"china": {
		scope: "https://vault.azure.cn/.default",
		url:   "https://%s.vault.azure.cn/",
	},
}

func getEnvironmentFromName(name, vault string) (*environment, error) {
	name = strings.ToLower(name)
	vault = strings.ToLower(vault)
	envTempl, found := environmentTemplates[name]
	if !found {
		return nil, fmt.Errorf("no azure environment name '%s'", name)
	}

	return &environment{
		scope: envTempl.scope,
		url:   fmt.Sprintf(envTempl.url, vault),
	}, nil
}
