package api

import (
	"context"
	"encoding/json"
)

// Secret is a Secret
type Secret struct {
	ID         string `json:"id,omitempty"`
	UserID     string `json:"user_id,omitempty"`
	ResourceID string `json:"resource_id,omitempty"`
	Data       string `json:"data,omitempty"`
	Created    *Time  `json:"created,omitempty"`
	Modified   *Time  `json:"modified,omitempty"`
}

type SecretDataTypePasswordAndDescription struct {
	Password    string `json:"password"`
	Description string `json:"description,omitempty"`
}

// GetSecret gets a Passbolt Secret
func (c *Client) GetSecret(ctx context.Context, resourceID string) (*Secret, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/secrets/resource/"+resourceID+".json", "v2", nil, nil)
	if err != nil {
		return nil, err
	}

	var secret Secret
	err = json.Unmarshal(msg.Body, &secret)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}
