package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/passbolt/go-passbolt/api"
)

// CreateResource creates a resource using the server's preferred format (v4 or v5).
// For more control, use CreateResourceGeneric.
func CreateResource(ctx context.Context, c *api.Client, folderParentID, name, username, uri, password, description string) (string, error) {
	var slug string
	if c.MetadataTypeSettings().DefaultResourceType == api.PassboltAPIVersionTypeV5 {
		slug = "v5-default"
	} else {
		slug = "password-and-description"
	}

	metadataFields := map[string]any{
		"name":     name,
		"username": username,
	}
	if strings.HasPrefix(slug, "v5-") {
		metadataFields["uris"] = []string{uri}
	} else {
		metadataFields["uri"] = uri
	}

	secretFields := map[string]any{
		"password":    password,
		"description": description,
	}

	return CreateResourceGeneric(ctx, c, slug, folderParentID, metadataFields, secretFields)
}

// CreateResourceGeneric creates a resource of any type using dynamic field maps.
// The slug determines the resource type. Metadata and secret fields are validated
// against the resource type's JSON schema before submission.
func CreateResourceGeneric(ctx context.Context, c *api.Client, slug string, folderParentID string, metadataFields map[string]any, secretFields map[string]any) (string, error) {
	// Find the resource type by slug
	rType, err := findResourceTypeBySlug(ctx, c, slug)
	if err != nil {
		return "", err
	}

	isV5 := rType.IsV5()

	// Check creation permissions
	if isV5 && !c.MetadataTypeSettings().AllowCreationOfV5Resources {
		return "", ErrV5CreationDisabled
	}
	if !isV5 && !c.MetadataTypeSettings().AllowCreationOfV4Resources {
		return "", ErrV4CreationDisabled
	}

	resource := api.Resource{
		ResourceTypeID: rType.ID,
		FolderParentID: folderParentID,
	}

	// Auto-route description between metadata and secret based on schema.
	// Callers may put description in either map; we move it to the right place.
	routeFieldBySchema(rType, metadataFields, secretFields, "description")

	// Normalize uri/uris based on schema (V4 uses "uri", V5 uses "uris" array)
	if err := normalizeURIField(rType, metadataFields); err != nil {
		return "", fmt.Errorf("normalizing URI field: %w", err)
	}

	// Validate custom fields before encryption (server can't validate encrypted content)
	if err := validateCustomFields(metadataFields, secretFields); err != nil {
		return "", fmt.Errorf("validating custom fields: %w", err)
	}

	// Build and set metadata
	if isV5 {
		// V5: encrypt metadata
		metadataFields["object_type"] = api.PassboltObjectTypeResourceMetadata
		metadataFields["resource_type_id"] = rType.ID

		metaData, err := json.Marshal(metadataFields)
		if err != nil {
			return "", fmt.Errorf("marshaling metadata: %w", err)
		}

		err = validateMetadata(rType, string(metaData))
		if err != nil {
			return "", fmt.Errorf("validating metadata: %w", err)
		}

		metadataKeyID, metadataKeyType, publicMetadataKey, err := c.GetMetadataKey(ctx, true)
		if err != nil {
			return "", fmt.Errorf("get metadata key: %w", err)
		}
		resource.MetadataKeyID = metadataKeyID
		resource.MetadataKeyType = metadataKeyType

		encMetadata, err := c.EncryptMessageWithKey(publicMetadataKey, string(metaData))
		if err != nil {
			return "", fmt.Errorf("encrypt metadata: %w", err)
		}
		resource.Metadata = encMetadata
	} else {
		// V4: set cleartext fields
		resource.Name = getStringField(metadataFields, "name")
		resource.Username = getStringField(metadataFields, "username")
		resource.URI = getStringField(metadataFields, "uri")
		resource.Description = getStringField(metadataFields, "description")
	}

	// Build and set secret
	var secretDataStr string
	if rType.IsSecretString() {
		// Secret is a plain string (password)
		secretDataStr = getStringField(secretFields, "password")
	} else {
		// Secret is JSON
		if isV5 {
			secretFields["object_type"] = api.PassboltObjectTypeSecretData
		}
		secretData, err := json.Marshal(secretFields)
		if err != nil {
			return "", fmt.Errorf("marshaling secret data: %w", err)
		}
		secretDataStr = string(secretData)
	}

	err = validateSecretData(rType, secretDataStr)
	if err != nil {
		return "", fmt.Errorf("validating secret data: %w", err)
	}

	encSecretData, err := c.EncryptMessage(secretDataStr)
	if err != nil {
		return "", fmt.Errorf("encrypting secret data for user me: %w", err)
	}
	resource.Secrets = []api.Secret{{Data: encSecretData}}

	// Handle password expiry
	passwordExpirySettings := c.GetPasswordExpirySettings()
	if passwordExpirySettings.DefaultExpiryPeriod != 0 {
		expiry := time.Now().Add(time.Hour * 24 * time.Duration(passwordExpirySettings.DefaultExpiryPeriod))
		resource.Expired = &api.Time{Time: expiry}
	}

	newresource, err := c.CreateResource(ctx, resource)
	if err != nil {
		return "", fmt.Errorf("creating resource: %w", err)
	}
	return newresource.ID, nil
}

// Deprecated: Use CreateResourceGeneric instead.
// CreateResourceV5 creates a v5-default resource. Delegates to CreateResourceGeneric.
func CreateResourceV5(ctx context.Context, c *api.Client, folderParentID, name, username, uri, password, description string) (string, error) {
	return CreateResourceGeneric(ctx, c, "v5-default", folderParentID,
		map[string]any{
			"name":     name,
			"username": username,
			"uris":     []string{uri},
		},
		map[string]any{
			"password":    password,
			"description": description,
		},
	)
}

// Deprecated: Use CreateResourceGeneric instead.
// CreateResourceV4 creates a v4 password-and-description resource. Delegates to CreateResourceGeneric.
func CreateResourceV4(ctx context.Context, c *api.Client, folderParentID, name, username, uri, password, description string) (string, error) {
	return CreateResourceGeneric(ctx, c, "password-and-description", folderParentID,
		map[string]any{
			"name":     name,
			"username": username,
			"uri":      uri,
		},
		map[string]any{
			"password":    password,
			"description": description,
		},
	)
}

// Deprecated: Use CreateResourceGeneric instead.
// CreateResourceSimple creates a legacy resource where only the password is encrypted.
func CreateResourceSimple(ctx context.Context, c *api.Client, folderParentID, name, username, uri, password, description string) (string, error) {
	if c.MetadataTypeSettings().DefaultResourceType == api.PassboltAPIVersionTypeV5 {
		return CreateResourceGeneric(ctx, c, "v5-password-string", folderParentID,
			map[string]any{
				"name":        name,
				"username":    username,
				"uris":        []string{uri},
				"description": description,
			},
			map[string]any{
				"password": password,
			},
		)
	}

	if !c.MetadataTypeSettings().AllowCreationOfV4Resources {
		return "", ErrV4CreationDisabled
	}

	enc, err := c.EncryptMessage(password)
	if err != nil {
		return "", fmt.Errorf("encrypting password: %w", err)
	}

	res := api.Resource{
		Name:           name,
		URI:            uri,
		Username:       username,
		FolderParentID: folderParentID,
		Description:    description,
		Secrets: []api.Secret{
			{Data: enc},
		},
	}

	resource, err := c.CreateResource(ctx, res)
	if err != nil {
		return "", fmt.Errorf("creating resource: %w", err)
	}
	return resource.ID, nil
}

// findResourceTypeBySlug finds a resource type by its slug from the server.
func findResourceTypeBySlug(ctx context.Context, c *api.Client, slug string) (*api.ResourceType, error) {
	types, err := c.GetResourceTypes(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("getting resource types: %w", err)
	}
	for _, t := range types {
		if t.Slug == slug {
			return &t, nil
		}
	}
	return nil, fmt.Errorf("%w: %v", ErrResourceTypeSlugNotFound, slug)
}

// routeFieldBySchema moves a field from metadataFields to secretFields (or vice versa)
// based on which schema section actually defines the field. This allows callers to put
// fields like "description" in either map without knowing the resource type internals.
func routeFieldBySchema(rType *api.ResourceType, metadataFields, secretFields map[string]any, field string) {
	inMeta := rType.HasMetadataField(field)
	inSecret := rType.HasSecretField(field)

	if val, ok := metadataFields[field]; ok && !inMeta && inSecret {
		// Caller put it in metadata but schema says it belongs in secret
		secretFields[field] = val
		delete(metadataFields, field)
	} else if val, ok := secretFields[field]; ok && !inSecret && inMeta {
		// Caller put it in secret but schema says it belongs in metadata
		metadataFields[field] = val
		delete(secretFields, field)
	}
}

// normalizeURIField converts between "uri" (string) and "uris" ([]string) in metadata
// based on what the resource type schema expects. This allows callers to always pass "uri"
// as a simple string without knowing whether the type uses V4's "uri" or V5's "uris".
// Returns an error if multiple URIs are provided but the schema only supports a single URI.
func normalizeURIField(rType *api.ResourceType, metadataFields map[string]any) error {
	wantsURIs := rType.HasMetadataField("uris")
	wantsURI := rType.HasMetadataField("uri")

	if val, ok := metadataFields["uri"]; ok && wantsURIs && !wantsURI {
		// Caller passed "uri" but schema expects "uris" array
		if s, ok := val.(string); ok {
			metadataFields["uris"] = []string{s}
			delete(metadataFields, "uri")
		}
	} else if val, ok := metadataFields["uris"]; ok && wantsURI && !wantsURIs {
		// Caller passed "uris" but schema expects "uri" string
		if arr, ok := val.([]string); ok && len(arr) > 0 {
			if len(arr) > 1 {
				return fmt.Errorf("resource type %q only supports a single URI, but %d were provided", rType.Slug, len(arr))
			}
			metadataFields["uri"] = arr[0]
			delete(metadataFields, "uris")
		} else if arr, ok := val.([]any); ok && len(arr) > 0 {
			if len(arr) > 1 {
				return fmt.Errorf("resource type %q only supports a single URI, but %d were provided", rType.Slug, len(arr))
			}
			if s, ok := arr[0].(string); ok {
				metadataFields["uri"] = s
				delete(metadataFields, "uris")
			}
		}
	}
	return nil
}
