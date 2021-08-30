package passbolt

import (
	"context"
	"encoding/json"
)

//Group is a Group
type Group struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Created    *Time  `json:"created,omitempty"`
	CreatedBy  string `json:"created_by,omitempty"`
	Deleted    bool   `json:"deleted,omitempty"`
	Modified   *Time  `json:"modified,omitempty"`
	ModifiedBy string `json:"modified_by,omitempty"`
	GroupUsers []User `json:"groups_users,omitempty"`
}

// GetGroupsOptions are all available query parameters
type GetGroupsOptions struct {
	FilterHasUsers    []string `url:"filter[has_users],omitempty"`
	FilterHasManagers []string `url:"filter[has-managers],omitempty"`

	ContainModifier        bool `url:"contain[modifier],omitempty"`
	ContainModifierProfile bool `url:"contain[modifier.profile],omitempty"`
	ContainUser            bool `url:"contain[user],omitempty"`
	ContainGroupUser       bool `url:"contain[group_user],omitempty"`
	ContainMyGroupUser     bool `url:"contain[my_group_user],omitempty"`
}

// GetGroups gets all Passbolt Groups
func (c *Client) GetGroups(ctx context.Context, opts *GetGroupsOptions) ([]Group, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/groups.json", "v2", nil, opts)
	if err != nil {
		return nil, err
	}

	var groups []Group
	err = json.Unmarshal(msg.Body, &groups)
	if err != nil {
		return nil, err
	}
	return groups, nil
}

// CreateGroup Creates a new Passbolt Group
func (c *Client) CreateGroup(ctx context.Context, group Group) (*Group, error) {
	msg, err := c.DoCustomRequest(ctx, "POST", "/groups.json", "v2", group, nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(msg.Body, &group)
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// GetGroup gets a Passbolt Group
func (c *Client) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/groups/"+groupID+".json", "v2", nil, nil)
	if err != nil {
		return nil, err
	}

	var group Group
	err = json.Unmarshal(msg.Body, &group)
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// UpdateGroup Updates a existing Passbolt Group
func (c *Client) UpdateGroup(ctx context.Context, groupID string, group Group) (*Group, error) {
	msg, err := c.DoCustomRequest(ctx, "PUT", "/groups/"+groupID+".json", "v2", group, nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(msg.Body, &group)
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// DeleteGroup Deletes a Passbolt Group
func (c *Client) DeleteGroup(ctx context.Context, groupID string) error {
	_, err := c.DoCustomRequest(ctx, "DELETE", "/groups/"+groupID+".json", "v2", nil, nil)
	if err != nil {
		return err
	}
	return nil
}
