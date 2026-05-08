package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ResourceType is the Type of a Resource
type ResourceType struct {
	ID          string          `json:"id,omitempty"`
	Slug        string          `json:"slug,omitempty"`
	Description string          `json:"description,omitempty"`
	Definition  json.RawMessage `json:"definition,omitempty"`
	Created     *Time           `json:"created,omitempty"`
	Modified    *Time           `json:"modified,omitempty"`
}

type ResourceTypeSchema struct {
	Resource map[string]any `json:"resource"`
	Secret   map[string]any `json:"secret"`
}

// IsSecretString returns true if the resource type's secret is a plain string (not JSON).
// This is determined by checking the "type" field of the secret section in the definition schema.
// Returns false if the definition cannot be parsed.
func (rt *ResourceType) IsSecretString() bool {
	schema, err := rt.parseSchema()
	if err != nil {
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

// HasSecretField returns true if the resource type's secret schema contains the given field.
func (rt *ResourceType) HasSecretField(field string) bool {
	schema, err := rt.parseSchema()
	if err != nil {
		return false
	}
	if rt.IsSecretString() {
		return false
	}
	props, ok := schema.Secret["properties"].(map[string]any)
	if !ok {
		return false
	}
	_, has := props[field]
	return has
}

// HasMetadataField returns true if the resource type's metadata schema contains the given field.
func (rt *ResourceType) HasMetadataField(field string) bool {
	schema, err := rt.parseSchema()
	if err != nil {
		return false
	}
	props, ok := schema.Resource["properties"].(map[string]any)
	if !ok {
		return false
	}
	_, has := props[field]
	return has
}

func (rt *ResourceType) parseSchema() (*ResourceTypeSchema, error) {
	definition := rt.Definition

	// Handle fallback schemas for broken servers
	if string(definition) == "[]" || string(definition) == "\"[]\"" {
		tmp, ok := ResourceSchemas[rt.Slug]
		if !ok {
			return nil, fmt.Errorf("no schema available for %v", rt.Slug)
		}
		definition = tmp
	}

	var schema ResourceTypeSchema
	err := json.Unmarshal(definition, &schema)
	if err != nil {
		// Workaround: sometimes schema is escaped as a string
		var tmp string
		if err2 := json.Unmarshal(definition, &tmp); err2 == nil {
			if err3 := json.Unmarshal([]byte(tmp), &schema); err3 == nil {
				return &schema, nil
			}
		}
		return nil, err
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
