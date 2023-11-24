package api

import (
	"context"
	"encoding/json"
	"fmt"
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
	Resource json.RawMessage `json:"resource"`
	Secret   json.RawMessage `json:"secret"`
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
		return nil, fmt.Errorf("Checking ID format: %w", err)
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
