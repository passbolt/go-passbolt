package api

import (
	"context"
	"encoding/json"
	"fmt"
)

// GPGKey is a GPGKey
type GPGKey struct {
	ID          string `json:"id,omitempty"`
	ArmoredKey  string `json:"armored_key,omitempty"`
	Created     *Time  `json:"created,omitempty"`
	KeyCreated  *Time  `json:"key_created,omitempty"`
	Bits        int    `json:"bits,omitempty"`
	Deleted     bool   `json:"deleted,omitempty"`
	Modified    *Time  `json:"modified,omitempty"`
	KeyID       string `json:"key_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Type        string `json:"type,omitempty"`
	Expires     *Time  `json:"expires,omitempty"`
}

// GetGPGKeysOptions are all available query parameters
type GetGPGKeysOptions struct {
	// This is a Unix TimeStamp
	FilterModifiedAfter int `url:"filter[modified-after],omitempty"`
}

// GetGPGKeys gets all Passbolt GPGKeys
func (c *Client) GetGPGKeys(ctx context.Context, opts *GetGPGKeysOptions) ([]GPGKey, error) {
	msg, err := c.DoCustomRequestV5(ctx, "GET", "/gpgkeys.json", nil, opts)
	if err != nil {
		return nil, err
	}

	var gpgkeys []GPGKey
	err = json.Unmarshal(msg.Body, &gpgkeys)
	if err != nil {
		return nil, err
	}
	return gpgkeys, nil
}

// GetGPGKey gets a Passbolt GPGKey
func (c *Client) GetGPGKey(ctx context.Context, gpgkeyID string) (*GPGKey, error) {
	err := checkUUIDFormat(gpgkeyID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequestV5(ctx, "GET", "/gpgkeys/"+gpgkeyID+".json", nil, nil)
	if err != nil {
		return nil, err
	}

	var gpgkey GPGKey
	err = json.Unmarshal(msg.Body, &gpgkey)
	if err != nil {
		return nil, err
	}
	return &gpgkey, nil
}
