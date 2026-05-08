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

// SecretDataTOTP represents the TOTP sub-object in secret data
type SecretDataTOTP struct {
	Algorithm string `json:"algorithm"`
	SecretKey string `json:"secret_key"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
}

// Deprecated: marshal/unmarshal secret data via map[string]any with helper.GetResourceFieldMaps
// or helper.CreateResourceGeneric instead. Will be removed in a future major version.
//
// SecretDataTypePasswordAndDescription is the format a secret of resource type "password-and-description" is stored in
type SecretDataTypePasswordAndDescription struct {
	Password    string `json:"password"`
	Description string `json:"description,omitempty"`
}

// Deprecated: marshal/unmarshal secret data via map[string]any with helper.GetResourceFieldMaps
// or helper.CreateResourceGeneric instead. Will be removed in a future major version.
//
// SecretDataTypeTOTP is the format a secret of resource type "totp" is stored in
type SecretDataTypeTOTP struct {
	TOTP SecretDataTOTP `json:"totp"`
}

// Deprecated: marshal/unmarshal secret data via map[string]any with helper.GetResourceFieldMaps
// or helper.CreateResourceGeneric instead. Will be removed in a future major version.
//
// SecretDataTypePasswordDescriptionTOTP is the format a secret of resource type "password-description-totp" is stored in
type SecretDataTypePasswordDescriptionTOTP struct {
	Password    string         `json:"password"`
	Description string         `json:"description,omitempty"`
	TOTP        SecretDataTOTP `json:"totp"`
}

// Deprecated: marshal/unmarshal secret data via map[string]any with helper.GetResourceFieldMaps
// or helper.CreateResourceGeneric instead. Will be removed in a future major version.
//
// SecretDataTypeV5Default represents the secret data for a V5 default resource.
type SecretDataTypeV5Default struct {
	ObjectType     string `json:"object_type"`
	ResourceTypeID string `json:"resource_type_id,omitempty"`
	Password       string `json:"password,omitempty"`
	Description    string `json:"description,omitempty"`
}

// Deprecated: marshal/unmarshal secret data via map[string]any with helper.GetResourceFieldMaps
// or helper.CreateResourceGeneric instead. Will be removed in a future major version.
//
// SecretDataTypeV5DefaultWithTOTP represents the secret data for a V5 default resource with TOTP.
type SecretDataTypeV5DefaultWithTOTP struct {
	ObjectType     string         `json:"object_type"`
	ResourceTypeID string         `json:"resource_type_id,omitempty"`
	Password       string         `json:"password,omitempty"`
	Description    string         `json:"description,omitempty"`
	TOTP           SecretDataTOTP `json:"totp"`
}

// Deprecated: marshal/unmarshal secret data via map[string]any with helper.GetResourceFieldMaps
// or helper.CreateResourceGeneric instead. Will be removed in a future major version.
//
// SecretDataTypeV5PasswordString is just the password directly.
type SecretDataTypeV5PasswordString string

// Deprecated: marshal/unmarshal secret data via map[string]any with helper.GetResourceFieldMaps
// or helper.CreateResourceGeneric instead. Will be removed in a future major version.
//
// SecretDataTypeV5TOTPStandalone represents the secret data for a V5 standalone TOTP resource.
type SecretDataTypeV5TOTPStandalone struct {
	ObjectType     string         `json:"object_type"`
	ResourceTypeID string         `json:"resource_type_id,omitempty"`
	TOTP           SecretDataTOTP `json:"totp"`
}

// GetSecret gets a Passbolt Secret
func (c *Client) GetSecret(ctx context.Context, resourceID string) (*Secret, error) {
	err := checkUUIDFormat(resourceID)
	if err != nil {
		return nil, fmt.Errorf("checking ID format: %w", err)
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
