package api

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

const PASSBOLT_OBJECT_TYPE_RESOURCE_METADATA = "PASSBOLT_RESOURCE_METADATA"
const PASSBOLT_OBJECT_TYPE_SECRET_DATA = "PASSBOLT_SECRET_DATA"

// ResourceMetadataTypeV5Default
type ResourceMetadataTypeV5Default struct {
	ObjectType     string   `json:"object_type"`
	ResourceTypeID string   `json:"resource_type_id,omitempty"`
	Name           string   `json:"name,omitempty"`
	Username       string   `json:"username,omitempty"`
	URIs           []string `json:"uris,omitempty"`
	Description    string   `json:"description,omitempty"`
}

// ResourceMetadataTypeV5DefaultWithTOTP
type ResourceMetadataTypeV5DefaultWithTOTP struct {
	ObjectType     string   `json:"object_type"`
	ResourceTypeID string   `json:"resource_type_id,omitempty"`
	Name           string   `json:"name,omitempty"`
	Username       string   `json:"username,omitempty"`
	URIs           []string `json:"uris,omitempty"`
	Description    string   `json:"description,omitempty"`
}

// ResourceMetadataTypeV5PasswordString
type ResourceMetadataTypeV5PasswordString struct {
	ObjectType     string   `json:"object_type"`
	ResourceTypeID string   `json:"resource_type_id,omitempty"`
	Name           string   `json:"name,omitempty"`
	Username       string   `json:"username,omitempty"`
	URIs           []string `json:"uris,omitempty"`
	Description    string   `json:"description,omitempty"`
}

// ResourceMetadataTypeV5TOTPStandalone
type ResourceMetadataTypeV5TOTPStandalone struct {
	ObjectType     string   `json:"object_type"`
	ResourceTypeID string   `json:"resource_type_id,omitempty"`
	Name           string   `json:"name,omitempty"`
	URIs           []string `json:"uris,omitempty"`
	Description    string   `json:"description,omitempty"`
}

func (c *Client) DecryptMetadata(metadataKey *crypto.Key, armoredCiphertext string) (string, error) {
	// TODO Get SessionKey from Cache
	var sessionKey *crypto.SessionKey = nil

	if sessionKey != nil {
		message, err := c.DecryptMessageWithSessionKey(sessionKey, armoredCiphertext)
		// If Decrypt was successfull
		if err == nil {
			return message, nil
		}
		// if this failed, fall through
	}

	metadata, newSessionKey, err := c.DecryptMessageWithPrivateKeyAndReturnSessionKey(metadataKey, armoredCiphertext)
	if err != nil {
		return "", fmt.Errorf("Decrypting Metadata: %w", err)
	}

	// TODO Save newSessionKey to cache
	_ = newSessionKey

	return metadata, nil
}

func (c *Client) EncryptMetadata(metadataKey *crypto.Key, data string) (string, error) {
	armoredCiphertext, err := c.EncryptMessageWithKey(metadataKey, data)
	if err != nil {
		return "", fmt.Errorf("Encrypting Metadata: %w", err)
	}

	// TODO save Session Key to cache

	return armoredCiphertext, nil
}
