package api

import (
	"context"
	"encoding/json"
	"fmt"
)

// Permission is a Permission
type Permission struct {
	ID            string `json:"id,omitempty"`
	ACO           string `json:"aco,omitempty"`
	ARO           string `json:"aro,omitempty"`
	ACOForeignKey string `json:"aco_foreign_key,omitempty"`
	AROForeignKey string `json:"aro_foreign_key,omitempty"`
	Type          int    `json:"type,omitempty"`
	Delete        bool   `json:"delete,omitempty"`
	IsNew         bool   `json:"is_new,omitempty"`
	Created       *Time  `json:"created,omitempty"`
	Modified      *Time  `json:"modified,omitempty"`
}

// GetResourcePermissions gets a Resources Permissions
func (c *Client) GetResourcePermissions(ctx context.Context, resourceID string) ([]Permission, error) {
	err := checkUUIDFormat(resourceID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequest(ctx, "GET", "/permissions/resource/"+resourceID+".json", "v2", nil, nil)
	if err != nil {
		return nil, err
	}

	var permissions []Permission
	err = json.Unmarshal(msg.Body, &permissions)
	if err != nil {
		return nil, err
	}
	return permissions, nil
}
