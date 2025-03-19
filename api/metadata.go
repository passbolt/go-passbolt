package api

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// ResourceMetadataTypePasswordAndDescription
type ResourceMetadataTypePasswordAndDescription struct {
	ObjectType     string   `json:"object_type"`
	ResourceTypeID string   `json:"resource_type_id,omitempty"`
	Name           string   `json:"name,omitempty"`
	Username       string   `json:"username,omitempty"`
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
