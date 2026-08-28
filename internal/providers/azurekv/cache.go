package azurekv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/goodieshq/signssh/internal/config"
)

// authCachePath returns the path to the authentication record file and the name of the cache for a given tenant/client pair
func authCachePath(tenantID string, clientID string) (string, string, error) {
	// get the os-depdendent user config directory
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", "", fmt.Errorf("determine user config directory: %w", err)
	}

	// create the app config dir if it doesn't exist
	dir := filepath.Join(configDir, config.AppName)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", fmt.Errorf("create %s config directory: %w", config.AppName, err)
	}

	// hash the tenant/client pair to create a unique ID for the cache
	sum := sha256.Sum256([]byte(tenantID + "\x00" + clientID))

	// use the first 12 bytes of the hash for brevity
	id := hex.EncodeToString(sum[:12])

	// return the path to the authentication record and the name of the cache
	fileName := filepath.Join(dir, "auth-"+id+".json")
	cacheName := config.AppName + "-" + id
	return fileName, cacheName, nil
}

func authCacheLoad(path string) (azidentity.AuthenticationRecord, error) {
	var record azidentity.AuthenticationRecord

	// read the authentication record from the file
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return azidentity.AuthenticationRecord{}, nil
	}

	if err != nil {
		return azidentity.AuthenticationRecord{}, err
	}

	// unmarshal the authentication record from the file
	if err := json.Unmarshal(data, &record); err != nil {
		// treat corrupted file as just an empty cache
		return azidentity.AuthenticationRecord{}, nil
	}

	return record, nil
}

func authCacheSave(path string, record azidentity.AuthenticationRecord) error {
	// marshal the authentication record to JSON
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode authentication record: %w", err)
	}

	// write the authentication record to the file with 0600 permissions
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write authentication record: %w", err)
	}

	return nil
}
