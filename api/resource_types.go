package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrSchemaUnavailable is returned by ResourceType.Schema when this SDK bundles no schema for
// the resource type's slug.
var ErrSchemaUnavailable = errors.New("no schema available for resource type")

// ResourceType is the Type of a Resource
type ResourceType struct {
	ID          string `json:"id,omitempty"`
	Slug        string `json:"slug,omitempty"`
	Description string `json:"description,omitempty"`
	// Definition is the schema the server reports. Informational only: validation uses the
	// bundle embedded in this SDK (see Schema).
	Definition json.RawMessage `json:"definition,omitempty"`
	Created    *Time           `json:"created,omitempty"`
	Modified   *Time           `json:"modified,omitempty"`
}

type ResourceTypeSchema struct {
	Resource map[string]any `json:"resource"`
	Secret   map[string]any `json:"secret"`
}

// IsSecretString reports whether the type's secret is a plain string rather than JSON.
// Returns false if this SDK bundles no schema for the slug.
func (rt *ResourceType) IsSecretString() bool {
	schema, ok := rt.bundledSchema()
	if !ok {
		return false
	}
	secretType, _ := schema.Secret["type"].(string)
	return secretType == "string"
}

// IsV5 returns true if this is a v5 resource type (has encrypted metadata).
// V5 resource types use a "v5-" slug prefix.
func (rt *ResourceType) IsV5() bool {
	return strings.HasPrefix(rt.Slug, "v5-")
}

// HasSecretField returns true if the resource type's bundled secret schema contains the given
// field. Returns false if this SDK bundles no schema for the slug.
func (rt *ResourceType) HasSecretField(field string) bool {
	schema, ok := rt.bundledSchema()
	if !ok {
		return false
	}
	// A plain-string secret has no fields.
	if secretType, _ := schema.Secret["type"].(string); secretType == "string" {
		return false
	}
	props, ok := schema.Secret["properties"].(map[string]any)
	if !ok {
		return false
	}
	_, has := props[field]
	return has
}

// HasMetadataField returns true if the resource type's bundled metadata schema contains the
// given field. Returns false if this SDK bundles no schema for the slug.
func (rt *ResourceType) HasMetadataField(field string) bool {
	schema, ok := rt.bundledSchema()
	if !ok {
		return false
	}
	props, ok := schema.Resource["properties"].(map[string]any)
	if !ok {
		return false
	}
	_, has := props[field]
	return has
}

// bundledSchema returns the shared parse of the type's bundled schema, or false when this SDK
// bundles none. The result is read-only: callers that need to modify a schema use Schema.
func (rt *ResourceType) bundledSchema() (*ResourceTypeSchema, bool) {
	schema, ok := parsedSchemas[rt.Slug]
	return schema, ok
}

// Schema returns a fresh copy of the type's bundled JSON Schema; rt.Definition is never used.
// A slug this SDK does not bundle yields an error wrapping ErrSchemaUnavailable.
func (rt *ResourceType) Schema() (*ResourceTypeSchema, error) {
	raw, ok := ResourceSchemas[rt.Slug]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSchemaUnavailable, rt.Slug)
	}

	var schema ResourceTypeSchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, fmt.Errorf("unmarshal schema for %q: %w", rt.Slug, err)
	}
	return &schema, nil
}

// GetResourceTypesOptions is a placeholder for future options
type GetResourceTypesOptions struct {
}

// GetResourceTypes gets all Passbolt Resource Types
func (c *Client) GetResourceTypes(ctx context.Context, opts *GetResourceTypesOptions) ([]ResourceType, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/resource-types.json", "v2", nil, opts)
	if err != nil {
		return nil, err
	}

	var types []ResourceType
	err = json.Unmarshal(msg.Body, &types)
	if err != nil {
		return nil, err
	}
	return types, nil
}

// GetResourceType gets a Passbolt Type
func (c *Client) GetResourceType(ctx context.Context, typeID string) (*ResourceType, error) {
	err := checkUUIDFormat(typeID)
	if err != nil {
		return nil, fmt.Errorf("checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequest(ctx, "GET", "/resource-types/"+typeID+".json", "v2", nil, nil)
	if err != nil {
		return nil, err
	}

	var rType ResourceType
	err = json.Unmarshal(msg.Body, &rType)
	if err != nil {
		return nil, err
	}
	return &rType, nil
}
