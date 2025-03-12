package api

import (
	"context"
	"encoding/json"
	"fmt"
)

// MetadataSessionKey is a MetadataSessionKey
type MetadataSessionKey struct {
	ID       string `json:"id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	Data     string `json:"data,omitempty"`
	Created  Time   `json:"created,omitempty"`
	Modified Time   `json:"modified,omitempty"`
}

// MetadataSessionKeyData is a MetadataSessionKeyData
type MetadataSessionKeyData struct {
	// ObjectType Must always be PASSBOLT_SESSION_KEYS
	ObjectType  string                          `json:"object_type,omitempty"`
	SessionKeys []MetadataSessionKeyDataElement `json:"session_keys,omitempty"`
}

// MetadataSessionKeyData is a MetadataSessionKeyData
type MetadataSessionKeyDataElement struct {
	ForeignModel ForeignModelTypes `json:"foreign_model"`
	ForeignID    string            `json:"foreign_id"`
	SessionKey   string            `json:"session_key"`
	Modified     Time              `json:"modified"`
}

// GetMetadataTypeSettings gets the Servers Settings about which Types to use
func (c *Client) GetMetadataSessionKeys(ctx context.Context) ([]MetadataSessionKey, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/metadata/session-keys.json", "v2", nil, nil)
	if err != nil {
		return nil, err
	}

	var metadataSessionKeys []MetadataSessionKey
	err = json.Unmarshal(msg.Body, &metadataSessionKeys)
	if err != nil {
		return nil, err
	}
	return metadataSessionKeys, nil
}

// TODO add Create and Update

// DeleteSessionKey Deletes a Passbolt SessionKey
func (c *Client) DeleteSessionKey(ctx context.Context, sessionKeyID string) error {
	err := checkUUIDFormat(sessionKeyID)
	if err != nil {
		return fmt.Errorf("Checking ID format: %w", err)
	}
	_, err = c.DoCustomRequest(ctx, "DELETE", "/metadata/session-keys/"+sessionKeyID+".json", "v2", nil, nil)
	if err != nil {
		return err
	}
	return nil
}
