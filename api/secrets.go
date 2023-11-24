package api

import (
	"context"
	"encoding/json"
	"fmt"
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

// SecretDataTypePasswordAndDescription is the format a secret of resource type "password-and-description" is stored in
type SecretDataTypePasswordAndDescription struct {
	Password    string `json:"password"`
	Description string `json:"description,omitempty"`
}

type SecretDataTOTP struct {
	Algorithm string `json:"algorithm"`
	SecretKey string `json:"secret_key"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
}

// SecretDataTypeTOTP is the format a secret of resource type "totp" is stored in
type SecretDataTypeTOTP struct {
	TOTP SecretDataTOTP `json:"totp"`
}

// SecretDataTypePasswordDescriptionTOTP is the format a secret of resource type "password-description-totp" is stored in
type SecretDataTypePasswordDescriptionTOTP struct {
	Password    string         `json:"password"`
	Description string         `json:"description,omitempty"`
	TOTP        SecretDataTOTP `json:"totp"`
}

// GetSecret gets a Passbolt Secret
func (c *Client) GetSecret(ctx context.Context, resourceID string) (*Secret, error) {
	err := checkUUIDFormat(resourceID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
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
