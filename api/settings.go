package api

import (
	"context"
	"encoding/json"
)

// ServerSettingsResponse contains all Servers Settings
type ServerSettingsResponse struct {
	Passbolt ServerPassboltSettings `json:"passbolt"`
}

// ServerPassboltSettings contains Passbolt specific server settings
type ServerPassboltSettings struct {
	Plugins map[string]ServerPassboltPluginSettings `json:"plugins"`
}

// ServerPassboltPluginSettings contains the Settings of a Specific Passbolt Plugin
type ServerPassboltPluginSettings struct {
	Enabled bool   `json:"enabled"`
	Version string `json:"version"`
}

// GetServerSettings gets the Server Settings
func (c *Client) GetServerSettings(ctx context.Context) (*ServerSettingsResponse, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/settings.json", "v3", nil, nil)
	if err != nil {
		return nil, err
	}

	var settings ServerSettingsResponse
	err = json.Unmarshal(msg.Body, &settings)
	if err != nil {
		return nil, err
	}
	return &settings, nil
}

func (ps *ServerPassboltSettings) IsPluginEnabled(name string) bool {
	p, ok := ps.Plugins[name]
	if !ok {
		return false
	}

	return p.Enabled
}
