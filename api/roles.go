package api

import (
	"context"
	"encoding/json"
)

// Role is a Role
type Role struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Created     *Time  `json:"created,omitempty"`
	Description string `json:"description,omitempty"`
	Modified    *Time  `json:"modified,omitempty"`
	Avatar      Avatar `json:"avatar,omitempty"`
}

// Avatar is a Users Avatar
type Avatar struct {
	ID         string `json:"id,omitempty"`
	UserID     string `json:"user_id,omitempty"`
	ForeignKey string `json:"foreign_key,omitempty"`
	Model      string `json:"model,omitempty"`
	Filename   string `json:"filename,omitempty"`
	Filesize   int    `json:"filesize,omitempty"`
	MimeType   string `json:"mime_type,omitempty"`
	Extension  string `json:"extension,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Path       string `json:"path,omitempty"`
	Adapter    string `json:"adapter,omitempty"`
	Created    *Time  `json:"created,omitempty"`
	Modified   *Time  `json:"modified,omitempty"`
	URL        *URL   `json:"url,omitempty"`
}

// URL is a Passbolt URL
type URL struct {
	Medium string `json:"medium,omitempty"`
	Small  string `json:"small,omitempty"`
}

// GetRoles gets all Passbolt Roles
func (c *Client) GetRoles(ctx context.Context) ([]Role, error) {
	msg, err := c.DoCustomRequestV5(ctx, "GET", "/roles.json", nil, nil)
	if err != nil {
		return nil, err
	}

	var roles []Role
	err = json.Unmarshal(msg.Body, &roles)
	if err != nil {
		return nil, err
	}
	return roles, nil
}
