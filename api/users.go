package api

import (
	"context"
	"encoding/json"
	"fmt"
)

const UserLocaleENUK = "en-UK"

// User contains information about a passbolt User
type User struct {
	// Read-only administrator/self data; nil means the server did not expose it.
	IsMFAEnabled *bool `json:"is_mfa_enabled,omitempty"`
	// Read-only optional SCIM directory linkage in the server's original schema.
	ScimEntry    json.RawMessage `json:"scim_entry,omitempty"`
	ID           string          `json:"id,omitempty"`
	Created      *Time           `json:"created,omitempty"`
	Active       bool            `json:"active,omitempty"`
	Deleted      bool            `json:"deleted,omitempty"`
	Disabled     *Time           `json:"disabled,omitempty"`
	Description  string          `json:"description,omitempty"`
	Favorite     *Favorite       `json:"favorite,omitempty"`
	Modified     *Time           `json:"modified,omitempty"`
	Username     string          `json:"username,omitempty"`
	RoleID       string          `json:"role_id,omitempty"`
	Profile      *Profile        `json:"profile,omitempty"`
	Role         *Role           `json:"role,omitempty"`
	GPGKey       *GPGKey         `json:"gpgkey,omitempty"`
	LastLoggedIn string          `json:"last_logged_in,omitempty"`
	Locale       string          `json:"locale,omitempty"`

	// Admin only, needs contains
	MissingMetadataKeyIDs []string `json:"missing_metadata_key_ids,omitempty"`

	// GroupsUsers contains group membership data (returned by SearchAROs endpoint)
	GroupsUsers []GroupMembership `json:"groups_users,omitempty"`
}

// Profile is a Profile
type Profile struct {
	ID        string  `json:"id,omitempty"`
	UserID    string  `json:"user_id,omitempty"`
	FirstName string  `json:"first_name,omitempty"`
	LastName  string  `json:"last_name,omitempty"`
	Created   *Time   `json:"created,omitempty"`
	Modified  *Time   `json:"modified,omitempty"`
	Avatar    *Avatar `json:"avatar,omitempty"`
}

// GetUserOptions selects optional user-view associations.
type GetUserOptions struct {
	ContainSCIMEntry bool `url:"contain[scim_entry],omitempty"`
}

// GetUsersOptions are available user index query parameters.
type GetUsersOptions struct {
	ContainIsMFAEnabled bool     `url:"contain[is_mfa_enabled],omitempty"`
	ContainSCIMEntry    bool     `url:"contain[scim_entry],omitempty"`
	FilterIsMFAEnabled  *bool    `url:"filter[is-mfa-enabled],omitempty"`
	FilterSearch        string   `url:"filter[search],omitempty"`
	FilterHasGroup      []string `url:"filter[has-groups][],omitempty"`
	FilterHasAccess     []string `url:"filter[has-access][],omitempty"`
	FilterIsAdmin       bool     `url:"filter[is-admin],omitempty"`

	ContainLastLoggedIn bool `url:"contain[LastLoggedIn],omitempty"`
	// Admin only
	MissingMetadataKeyIDs bool `url:"contain[missing_metadata_key_ids],omitempty"`
}

// GetUsers gets all Passbolt Users
func (c *Client) GetUsers(ctx context.Context, opts *GetUsersOptions) ([]User, error) {
	if opts != nil && opts.FilterIsMFAEnabled != nil {
		copied := *opts
		copied.ContainIsMFAEnabled = true
		opts = &copied
	}
	return doList[User](ctx, c, "/users.json", opts)
}

// CreateUser Creates a new Passbolt User
func (c *Client) CreateUser(ctx context.Context, user User) (*User, error) {
	return doSave(ctx, c, "POST", "/users.json", user)
}

// GetMe gets the currently logged in Passbolt User
func (c *Client) GetMe(ctx context.Context) (*User, error) {
	return c.GetUser(ctx, "me")
}

// GetUser gets a Passbolt User
func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	return c.GetUserWithOptions(ctx, userID, nil)
}

// GetUserWithOptions gets a user with optional server-supported associations.
// The SCIM association requires administrator privileges and the SCIM plugin.
func (c *Client) GetUserWithOptions(ctx context.Context, userID string, opts *GetUserOptions) (*User, error) {
	if userID != "me" {
		if err := checkUUIDFormat(userID); err != nil {
			return nil, fmt.Errorf("checking ID format: %w", err)
		}
	}
	return doInto[User](ctx, c, "GET", "/users/"+userID+".json", nil, opts)
}

// UpdateUser Updates a existing Passbolt User
func (c *Client) UpdateUser(ctx context.Context, userID string, user User) (*User, error) {
	if userID != "me" {
		if err := checkUUIDFormat(userID); err != nil {
			return nil, fmt.Errorf("checking ID format: %w", err)
		}
	}
	return doSave(ctx, c, "PUT", "/users/"+userID+".json", user)
}

// DeleteUser Deletes a Passbolt User
func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	if userID != "me" {
		if err := checkUUIDFormat(userID); err != nil {
			return fmt.Errorf("checking ID format: %w", err)
		}
	}
	return doDelete(ctx, c, "/users/"+userID+".json")
}

// DeleteUserDryrun Check if a Passbolt User is Deleteable
func (c *Client) DeleteUserDryrun(ctx context.Context, userID string) error {
	if err := checkUUIDFormat(userID); err != nil {
		return fmt.Errorf("checking ID format: %w", err)
	}
	return doDelete(ctx, c, "/users/"+userID+"/dry-run.json")
}
