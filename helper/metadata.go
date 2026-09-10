package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/passbolt/go-passbolt/api"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaCache caches compiled JSON schemas by resource type ID
var (
	schemaCache   = make(map[string]*jsonschema.Schema)
	schemaCacheMu sync.RWMutex
)

// GetResourceMetadata decrypts a v5 resource's metadata, validating leniently so undeclared
// properties survive. Use GetResourceMetadataForWrite when the result will be stored again.
func GetResourceMetadata(ctx context.Context, c *api.Client, resource *api.Resource, rType *api.ResourceType) (string, error) {
	// First, check if we have a pre-fetched session key for this resource
	// This avoids unnecessary key copy operations when cache hits
	if cachedSessionKey := c.GetSessionKeyByResourceID(resource.ID); cachedSessionKey != nil {
		decMetadata, err := c.DecryptMetadataWithResourceID(resource.ID, "", nil, resource.Metadata)
		if err == nil {
			err = validateMetadata(rType, decMetadata)
			if err != nil {
				return "", fmt.Errorf("validate Metadata: %w", err)
			}
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

	err = validateMetadata(rType, decMetadata)
	if err != nil {
		return "", fmt.Errorf("validate Metadata: %w", err)
	}

	return decMetadata, nil
}

func validateMetadata(rType *api.ResourceType, metadata string) error {
	// Check schema cache first
	schemaCacheMu.RLock()
	schema, cached := schemaCache[rType.ID]
	schemaCacheMu.RUnlock()

	if !cached {
		schemaDefinition, err := rType.Schema()
		if err != nil {
			if errors.Is(err, api.ErrSchemaUnavailable) {
				return fmt.Errorf("%w: %v", ErrUnsupportedResourceType, rType.Slug)
			}
			return fmt.Errorf("resolving schema: %w", err)
		}

		comp := jsonschema.NewCompiler()

		err = comp.AddResource("urn:passbolt:schema:metadata", schemaDefinition.Resource)
		if err != nil {
			return fmt.Errorf("adding Json Schema: %w", err)
		}

		schema, err = comp.Compile("urn:passbolt:schema:metadata")
		if err != nil {
			return fmt.Errorf("compiling Json Schema: %w", err)
		}

		// Cache the compiled schema
		schemaCacheMu.Lock()
		schemaCache[rType.ID] = schema
		schemaCacheMu.Unlock()
	}

	var parsedMetadata map[string]any
	err := json.Unmarshal([]byte(metadata), &parsedMetadata)
	if err != nil {
		return fmt.Errorf("unmarshal Secret: %w", err)
	}

	err = schema.Validate(parsedMetadata)
	if err != nil {
		return fmt.Errorf("validating Metadata with Schema: %w", err)
	}
	return nil
}
