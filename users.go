package passbolt

import (
	"context"
	"encoding/json"
)

// User contains information about a passbolt User
type User struct {
	ID           string    `json:"id,omitempty"`
	Created      *Time     `json:"created,omitempty"`
	Active       bool      `json:"active,omitempty"`
	Deleted      bool      `json:"deleted,omitempty"`
	Description  string    `json:"description,omitempty"`
	Favorite     *Favorite `json:"favorite,omitempty"`
	Modified     *Time     `json:"modified,omitempty"`
	Username     string    `json:"username,omitempty"`
	RoleID       string    `json:"role_id,omitempty"`
	Profile      *Profile  `json:"profile,omitempty"`
	Role         *Role     `json:"role,omitempty"`
	GPGKey       *GPGKey   `json:"gpgKey,omitempty"`
	LastLoggedIn string    `json:"last_logged_in,omitempty"`
}

// Profile is a Profile
type Profile struct {
	ID        string `json:"id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Created   *Time  `json:"created,omitempty"`
	Modified  *Time  `json:"modified,omitempty"`
}

// GetUsersOptions are all available query parameters
type GetUsersOptions struct {
	FilterSearch    string `url:"filter[search],omitempty"`
	FilterHasGroup  string `url:"filter[has-group],omitempty"`
	FilterHasAccess string `url:"filter[has-access],omitempty"`
	FilterIsAdmin   bool   `url:"filter[is-admin],omitempty"`

	ContainLastLoggedIn bool `url:"contain[LastLoggedIn],omitempty"`
}

// GetUsers gets all Passbolt Users
func (c *Client) GetUsers(ctx context.Context, opts *GetUsersOptions) ([]User, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/users.json", "v2", nil, opts)
	if err != nil {
		return nil, err
	}

	var users []User
	err = json.Unmarshal(msg.Body, &users)
	if err != nil {
		return nil, err
	}
	return users, nil
}

// CreateUser Creates a new Passbolt User
func (c *Client) CreateUser(ctx context.Context, user User) (*User, error) {
	msg, err := c.DoCustomRequest(ctx, "POST", "/users.json", "v2", user, nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(msg.Body, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetMe gets the currently logged in Passbolt User
func (c *Client) GetMe(ctx context.Context) (*User, error) {
	return c.GetUser(ctx, "me")
}

// GetUser gets a Passbolt User
func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/users/"+userID+".json", "v2", nil, nil)
	if err != nil {
		return nil, err
	}

	var user User
	err = json.Unmarshal(msg.Body, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateUser Updates a existing Passbolt User
func (c *Client) UpdateUser(ctx context.Context, userID string, user User) (*User, error) {
	msg, err := c.DoCustomRequest(ctx, "PUT", "/users/"+userID+".json", "v2", user, nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(msg.Body, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// DeleteUser Deletes a Passbolt User
func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	_, err := c.DoCustomRequest(ctx, "DELETE", "/users/"+userID+".json", "v2", nil, nil)
	if err != nil {
		return err
	}
	return nil
}

// DeleteUserDryrun Check if a Passbolt User is Deleteable
func (c *Client) DeleteUserDryrun(ctx context.Context, userID string) error {
	_, err := c.DoCustomRequest(ctx, "DELETE", "/users/"+userID+"/dry-run.json", "v2", nil, nil)
	if err != nil {
		return err
	}
	return nil
}
