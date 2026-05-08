package helper

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/passbolt/go-passbolt/api"
)

// GetResource gets a resource by ID and returns its decrypted fields.
func GetResource(ctx context.Context, c *api.Client, resourceID string) (folderParentID, name, username, uri, password, description string, err error) {
	resource, err := c.GetResource(ctx, resourceID)
	if err != nil {
		return "", "", "", "", "", "", fmt.Errorf("getting resource: %w", err)
	}

	rType, err := c.GetResourceType(ctx, resource.ResourceTypeID)
	if err != nil {
		return "", "", "", "", "", "", fmt.Errorf("getting resource type: %w", err)
	}
	secret, err := c.GetSecret(ctx, resource.ID)
	if err != nil {
		return "", "", "", "", "", "", fmt.Errorf("getting resource secret: %w", err)
	}
	return GetResourceFromData(c, *resource, *secret, *rType)
}

// GetResourceFromData decrypts resources using only local data. The Resource object must include the secret.
// With v5 this needs network calls for metadata of v5 resources.
func GetResourceFromData(c *api.Client, resource api.Resource, secret api.Secret, rType api.ResourceType) (string, string, string, string, string, string, error) {
	return GetResourceFromDataWithOptions(c, resource, secret, rType, true)
}

// GetResourceFromDataWithOptions decrypts resources with option to skip secret decryption.
// For v5 resources, metadata (name, username, uri) can be decrypted without the secret.
// Set decryptSecret=false to skip secret decryption (password/description will be empty).
func GetResourceFromDataWithOptions(c *api.Client, resource api.Resource, secret api.Secret, rType api.ResourceType, decryptSecret bool) (string, string, string, string, string, string, error) {
	ctx := context.TODO()

	// Decrypt secret data if requested
	var rawSecretData string
	var err error
	if decryptSecret && secret.Data != "" {
		rawSecretData, err = c.DecryptSecretWithResourceID(resource.ID, secret.Data)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("decrypting secret data: %w", err)
		}

		err = validateSecretData(&rType, rawSecretData)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("validate secret data: %w", err)
		}
	}

	// Parse metadata.
	// V5 detection uses metadata presence (not rType.IsV5()) because we need to know
	// how this specific resource was stored, not what the type slug suggests.
	var metadataFields map[string]any
	isV5 := resource.Metadata != ""

	if isV5 {
		// V5: decrypt metadata
		rawMetadata, err := GetResourceMetadata(ctx, c, &resource, &rType)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("getting metadata: %w", err)
		}

		metadataFields = make(map[string]any)
		if err := json.Unmarshal([]byte(rawMetadata), &metadataFields); err != nil {
			return "", "", "", "", "", "", fmt.Errorf("parsing decrypted metadata: %w", err)
		}
	} else {
		// V4: metadata is in cleartext fields
		metadataFields = map[string]any{
			"name":        resource.Name,
			"username":    resource.Username,
			"uri":         resource.URI,
			"description": resource.Description,
		}
	}

	// Parse secret
	var secretFields map[string]any
	if rawSecretData != "" {
		if rType.IsSecretString() {
			secretFields = map[string]any{
				"password": rawSecretData,
			}
		} else {
			secretFields = make(map[string]any)
			if err := json.Unmarshal([]byte(rawSecretData), &secretFields); err != nil {
				return "", "", "", "", "", "", fmt.Errorf("parsing decrypted secret data: %w", err)
			}
		}
	}

	// Extract standard fields from maps
	name := GetStringField(metadataFields, "name")
	username := GetStringField(metadataFields, "username")

	// URI: v4 uses "uri", v5 uses "uris" array
	uri := GetStringField(metadataFields, "uri")
	if uri == "" {
		if uris, ok := metadataFields["uris"].([]any); ok && len(uris) > 0 {
			if s, ok := uris[0].(string); ok {
				uri = s
			}
		}
	}

	password := GetStringField(secretFields, "password")

	// Description: check metadata first, then secret
	description := GetStringField(metadataFields, "description")
	if description == "" {
		description = GetStringField(secretFields, "description")
	}

	return resource.FolderParentID, name, username, uri, password, description, nil
}

// GetResourceFieldMaps decrypts a resource and returns the metadata and secret field maps.
// This is useful for callers that need access to custom fields beyond the standard
// name/username/uri/password/description; those standard fields can be read from the
// returned maps with GetStringField.
func GetResourceFieldMaps(c *api.Client, resource api.Resource, secret api.Secret, rType api.ResourceType, decryptSecret bool) (folderParentID string, metadataFields, secretFields map[string]any, err error) {
	ctx := context.TODO()

	// Decrypt secret data if requested
	var rawSecretData string
	if decryptSecret && secret.Data != "" {
		rawSecretData, err = c.DecryptSecretWithResourceID(resource.ID, secret.Data)
		if err != nil {
			return "", nil, nil, fmt.Errorf("decrypting secret data: %w", err)
		}

		err = validateSecretData(&rType, rawSecretData)
		if err != nil {
			return "", nil, nil, fmt.Errorf("validate secret data: %w", err)
		}
	}

	// Parse metadata
	isV5 := resource.Metadata != ""

	if isV5 {
		rawMetadata, err := GetResourceMetadata(ctx, c, &resource, &rType)
		if err != nil {
			return "", nil, nil, fmt.Errorf("getting metadata: %w", err)
		}

		metadataFields = make(map[string]any)
		if err := json.Unmarshal([]byte(rawMetadata), &metadataFields); err != nil {
			return "", nil, nil, fmt.Errorf("parsing decrypted metadata: %w", err)
		}
	} else {
		metadataFields = map[string]any{
			"name":        resource.Name,
			"username":    resource.Username,
			"uri":         resource.URI,
			"description": resource.Description,
		}
	}

	// Parse secret
	if rawSecretData != "" {
		if rType.IsSecretString() {
			secretFields = map[string]any{
				"password": rawSecretData,
			}
		} else {
			secretFields = make(map[string]any)
			if err := json.Unmarshal([]byte(rawSecretData), &secretFields); err != nil {
				return "", nil, nil, fmt.Errorf("parsing decrypted secret data: %w", err)
			}
		}
	}

	// Normalize maps so CEL filters can use consistent keys regardless of v4/v5.
	// Always add "uri" to metadata if missing (v5 schema uses "uris" array).
	if _, ok := metadataFields["uri"]; !ok {
		uri := ""
		if uris, ok := metadataFields["uris"].([]any); ok && len(uris) > 0 {
			if s, ok := uris[0].(string); ok {
				uri = s
			}
		}
		metadataFields["uri"] = uri
	}
	// Always add "description" to metadata if missing or empty: v5 and v4
	// password-and-description both store description in the encrypted secret,
	// leaving the metadata-side value blank.
	if d, _ := metadataFields["description"].(string); d == "" {
		metadataFields["description"] = GetStringField(secretFields, "description")
	}

	return resource.FolderParentID, metadataFields, secretFields, nil
}

// GetStringField safely extracts a string from a map. Returns "" if the key is
// missing or the value isn't a string.
func GetStringField(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
