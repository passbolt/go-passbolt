package helper

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/passbolt/go-passbolt/api"
)

// GetResourceMetadata decrypts a v5 resource's metadata, validating leniently so undeclared
// properties survive. Use GetResourceMetadataForWrite when the result will be stored again.
func GetResourceMetadata(ctx context.Context, c *api.Client, resource *api.Resource, rType *api.ResourceType) (string, error) {
	return getResourceMetadata(ctx, c, resource, rType, validateRead)
}

// GetResourceMetadataForWrite decrypts metadata that will be re-encrypted and stored, validating
// strictly; extra properties yield an error wrapping ErrSchemaMismatch.
func GetResourceMetadataForWrite(ctx context.Context, c *api.Client, resource *api.Resource, rType *api.ResourceType) (string, error) {
	return getResourceMetadata(ctx, c, resource, rType, validateWrite)
}

func getResourceMetadata(ctx context.Context, c *api.Client, resource *api.Resource, rType *api.ResourceType, mode validationMode) (string, error) {
	metadata, err := decryptResourceMetadata(ctx, c, resource)
	if err != nil {
		return "", err
	}
	if err := validateMetadata(rType, metadata, mode); err != nil {
		return "", fmt.Errorf("validate Metadata: %w", err)
	}
	return metadata, nil
}

// decryptResourceMetadata decrypts a v5 resource's metadata without validating it. Update uses
// it for the merge base: the stored document may be invalid, and the update is what repairs it.
func decryptResourceMetadata(ctx context.Context, c *api.Client, resource *api.Resource) (string, error) {
	// A pre-fetched session key for this resource avoids the key copy below on a cache hit.
	if cachedSessionKey := c.GetSessionKeyByResourceID(resource.ID); cachedSessionKey != nil {
		decMetadata, err := c.DecryptMetadataWithResourceID(resource.ID, "", nil, resource.Metadata)
		if err == nil {
			return decMetadata, nil
		}
		// If decrypt failed, fall through to full decryption path
	}

	var metadatakey *crypto.Key
	var metadataKeyID string

	if resource.MetadataKeyType == api.MetadataKeyTypeUserKey {
		tmp, err := c.GetUserPrivateKeyCopy()
		if err != nil {
			return "", fmt.Errorf("get Private Key Copy: %w", err)
		}
		metadatakey = tmp
		// Use user key fingerprint as cache key to enable session key caching
		metadataKeyID = "user-key:" + tmp.GetFingerprint()
	} else {
		// Use cached decrypted metadata key
		metadataKeyID = resource.MetadataKeyID
		key, err := c.GetDecryptedMetadataKeyCached(ctx, metadataKeyID)
		if err != nil {
			return "", fmt.Errorf("get Metadata Key by ID: %w", err)
		}
		metadatakey = key
	}

	// Use resource-aware decryption that checks pre-fetched session keys first
	// This provides optimal performance when PreFetchCaches() has been called during login
	decMetadata, err := c.DecryptMetadataWithResourceID(resource.ID, metadataKeyID, metadatakey, resource.Metadata)
	if err != nil {
		return "", fmt.Errorf("decrypt Metadata: %w", err)
	}
	return decMetadata, nil
}

func validateMetadata(rType *api.ResourceType, metadata string, mode validationMode) error {
	schema, err := compileSection(rType, schemaSectionResource, mode)
	if err != nil {
		return err
	}

	var parsedMetadata map[string]any
	if err := json.Unmarshal([]byte(metadata), &parsedMetadata); err != nil {
		return fmt.Errorf("unmarshal Metadata: %w", err)
	}

	if err := schema.Validate(parsedMetadata); err != nil {
		return wrapValidationError("Metadata", err)
	}
	return nil
}
