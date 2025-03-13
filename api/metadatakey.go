package api

import (
	"context"
	"encoding/json"
)

type MetadataKeyType string

const (
	MetadataKeyTypeUserKey   MetadataKeyType = "user_key"
	MetadataKeyTypeSharedKey                 = "shared_key"
)

func (s MetadataKeyType) IsValid() bool {
	switch s {
	case MetadataKeyTypeUserKey, MetadataKeyTypeSharedKey:
		return true
	}
	return false
}

// MetadataKey is a MetadataKey
type MetadataKey struct {
	ID          string `json:"id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ArmoredKey  string `json:"armored_key,omitempty"`
	Created     Time   `json:"created,omitempty"`
	Modified    Time   `json:"modified,omitempty"`

	// These are always null? Used for Key Rotation?
	//"expired": null,
	//"deleted": null,

	CreatedBy  *string `json:"created_by,omitempty"`
	ModifiedBy *string `json:"modified_by,omitempty"`

	MetadataPrivateKeys []MetadataPrivateKey `json:"metadata_private_keys,omitempty"`
}

// MetadataPrivateKey is a MetadataPrivateKey
type MetadataPrivateKey struct {
	ID            string  `json:"id,omitempty"`
	MetadataKeyID string  `json:"metadata_key_id,omitempty"`
	UserID        *string `json:"user_id,omitempty"` // TODO, is this nullable. The Docs says yes and no
	Data          string  `json:"data,omitempty"`
	Created       Time    `json:"created,omitempty"`
	Modified      Time    `json:"modified,omitempty"`
	CreatedBy     *string `json:"created_by,omitempty"`
	ModifiedBy    *string `json:"modified_by,omitempty"`
}

// MetadataPrivateKeyData is a MetadataPrivateKeyData
type MetadataPrivateKeyData struct {
	// ObjectType Must always be PASSBOLT_METADATA_PRIVATE_KEY
	ObjectType string `json:"object_type,omitempty"`
	// Domain Must be the Passbolt Server URL
	Domain      string `json:"domain,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ArmoredKey  string `json:"armored_key,omitempty"`
	// Passphrase must be Empty for Server Keys
	Passphrase string `json:"passphrase,omitempty"`
}

// GetMetadataKeysOptions are all available query parameters
type GetMetadataKeysOptions struct {
	FilterDeleted bool `url:"filter[deleted],omitempty"`
	FilterExpired bool `url:"filter[expired],omitempty"`

	ContainMetadataPrivateKeys bool `url:"contain[metadata_private_keys],omitempty"`
}

// GetMetadataKeys gets all Passbolt GetMetadataKeys
func (c *Client) GetMetadataKeys(ctx context.Context, opts *GetMetadataKeysOptions) ([]MetadataKey, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/metadata/keys.json", "v2", nil, opts)
	if err != nil {
		return nil, err
	}

	var metadataKeys []MetadataKey
	err = json.Unmarshal(msg.Body, &metadataKeys)
	if err != nil {
		return nil, err
	}
	return metadataKeys, nil
}
