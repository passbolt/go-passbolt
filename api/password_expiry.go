package api

import (
	"context"
	"encoding/json"
	"time"
)

// PasswordExpirySettings contains the Password expiry settings
type PasswordExpirySettings struct {
	ID                       string    `json:"id"`
	DefaultExpiryPeriod      int       `json:"default_expiry_period,omitempty"`
	PolicyOverride           bool      `json:"policy_override"`
	AutomaticExpiry          bool      `json:"automatic_expiry"`
	AutomaticUpdate          bool      `json:"automatic_update"`
	ExpiryNotificationPeriod int       `json:"expiry_notification_period,omitempty"`
	Created                  time.Time `json:"created"`
	Modified                 time.Time `json:"modified"`
	CreatedBy                string    `json:"created_by"`
	ModifiedBy               string    `json:"modified_by"`
}

// getServerPasswordExpirySettings gets the servers password expiry settings
func (c *Client) getServerPasswordExpirySettings(ctx context.Context) (*PasswordExpirySettings, error) {
	msg, err := c.DoCustomRequestV5(ctx, "GET", "/password-expiry/settings.json", nil, nil)
	if err != nil {
		return nil, err
	}

	var passwordExpirySettings PasswordExpirySettings
	err = json.Unmarshal(msg.Body, &passwordExpirySettings)
	if err != nil {
		return nil, err
	}
	return &passwordExpirySettings, nil
}

func getDefaultPasswordExpirySettings() PasswordExpirySettings {
	return PasswordExpirySettings{
		ID:                       "default",
		DefaultExpiryPeriod:      0,
		PolicyOverride:           false,
		AutomaticExpiry:          false,
		AutomaticUpdate:          false,
		ExpiryNotificationPeriod: 0,
		Created:                  time.Now(),
		Modified:                 time.Now(),
		CreatedBy:                "default",
	}
}
