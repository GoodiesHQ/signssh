package azurekv

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity/cache"
)

const managedIdentityProbeTimeout = 3 * time.Second

func newCredential(ctx context.Context, tenantID, clientID, scope string) (azcore.TokenCredential, error) {
	// try a managed identity first
	if cred, ok := tryManagedIdentity(ctx, scope); ok {
		return cred, nil
	}

	// build the cache path and name
	recordPath, cacheName, err := authCachePath(tenantID, clientID)
	if err != nil {
		return nil, err
	}

	// load the authentication record from disk, if it exists
	record, err := authCacheLoad(recordPath)
	if err != nil {
		return nil, fmt.Errorf("load authentication record: %w", err)
	}

	// create a persistent token cache for this tenant/client combination
	tokenCache, err := cache.New(&cache.Options{
		Name: cacheName,
	})
	if err != nil {
		return nil, fmt.Errorf("create persistent authentication cache: %w", err)
	}

	cred, err := azidentity.NewInteractiveBrowserCredential(
		&azidentity.InteractiveBrowserCredentialOptions{
			TenantID:             tenantID,
			ClientID:             clientID,
			Cache:                tokenCache,
			AuthenticationRecord: record,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create interactive browser credential: %w", err)
	}

	// A zero AuthenticationRecord means this machine/user hasn't authenticated to this tenant/client yet
	if record == (azidentity.AuthenticationRecord{}) {
		record, err = cred.Authenticate(ctx, &policy.TokenRequestOptions{
			Scopes:    []string{scope},
			EnableCAE: true,
		})
		if err != nil {
			return nil, fmt.Errorf("interactive authentication failed: %w", err)
		}

		if err := authCacheSave(recordPath, record); err != nil {
			return nil, fmt.Errorf("save authentication record: %w", err)
		}
	}

	return cred, nil
}

// tryManagedIdentity returns a system-assigned managed identity if one exists
func tryManagedIdentity(ctx context.Context, scope string) (azcore.TokenCredential, bool) {
	cred, err := azidentity.NewManagedIdentityCredential(nil)
	if err != nil {
		return nil, false
	}

	probeCtx, cancel := context.WithTimeout(ctx, managedIdentityProbeTimeout)
	defer cancel()

	if _, err := cred.GetToken(probeCtx, policy.TokenRequestOptions{
		Scopes: []string{scope},
	}); err != nil {
		return nil, false
	}

	return cred, true
}
