package api

import (
	"context"
	"encoding/json"
	"fmt"
)

// Group is a Group
type Group struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Created    *Time  `json:"created,omitempty"`
	CreatedBy  string `json:"created_by,omitempty"`
	Deleted    bool   `json:"deleted,omitempty"`
	Modified   *Time  `json:"modified,omitempty"`
	ModifiedBy string `json:"modified_by,omitempty"`
	// This does not Contain Profile for Users Anymore...
	GroupUsers []GroupMembership `json:"groups_users,omitempty"`
	// This is new and undocumented but as all the data
	Users []GroupUser `json:"users,omitempty"`
}

type GroupUser struct {
	User
	JoinData GroupJoinData `json:"_join_data,omitempty"`
}

type GroupJoinData struct {
	ID      string `json:"id,omitempty"`
	GroupID string `json:"group_id,omitempty"`
	UserID  string `json:"user_id,omitempty"`
	IsAdmin bool   `json:"is_admin,omitempty"`
	Created *Time  `json:"created,omitempty"`
}

type GroupMembership struct {
	ID      string `json:"id,omitempty"`
	UserID  string `json:"user_id,omitempty"`
	GroupID string `json:"group_id,omitempty"`
	IsAdmin bool   `json:"is_admin,omitempty"`
	Delete  bool   `json:"delete,omitempty"`
	User    User   `json:"user,omitempty"`
	Created *Time  `json:"created,omitempty"`
}

type GroupUpdate struct {
	Name         string            `json:"name,omitempty"`
	GroupChanges []GroupMembership `json:"groups_users,omitempty"`
	Secrets      []Secret          `json:"secrets,omitempty"`
}

// GetGroupsOptions are all available query parameters
type GetGroupsOptions struct {
	FilterHasUsers    []string `url:"filter[has_users],omitempty"`
	FilterHasManagers []string `url:"filter[has-managers],omitempty"`

	ContainModifier               bool `url:"contain[modifier],omitempty"`
	ContainModifierProfile        bool `url:"contain[modifier.profile],omitempty"`
	ContainMyGroupUser            bool `url:"contain[my_group_user],omitempty"`
	ContainUsers                  bool `url:"contain[users],omitempty"`
	ContainGroupsUsers            bool `url:"contain[groups_users],omitempty"`
	ContainGroupsUsersUser        bool `url:"contain[groups_users.user],omitempty"`
	ContainGroupsUsersUserProfile bool `url:"contain[groups_users.user.profile],omitempty"`
	ContainGroupsUsersUserGPGKey  bool `url:"contain[groups_users.user.gpgkey],omitempty"`
}

// UpdateGroupDryRunResult is the Result of a Update Group DryRun
type UpdateGroupDryRunResult struct {
	DryRun UpdateGroupDryRun `json:"dry-run,omitempty"`
}

// UpdateGroupDryRun contains the Actual Secrets Needed to update the group
type UpdateGroupDryRun struct {
	// for which users the secrets need to be reencrypted
	SecretsNeeded []UpdateGroupSecretsNeededContainer `json:"SecretsNeeded,omitempty"`
	// secrets needed to be reencrypted
	Secrets []GroupSecret `json:"Secrets,omitempty"`
}

// GroupSecret is a unnessesary container...
type GroupSecret struct {
	Secret []Secret `json:"secret,omitempty"`
}

// UpdateGroupSecretsNeededContainer is a unnessesary container...
type UpdateGroupSecretsNeededContainer struct {
	Secret UpdateGroupDryRunSecretsNeeded `json:"Secret,omitempty"`
}

// UpdateGroupDryRunSecretsNeeded a secret that needs to be reencrypted for a specific user
type UpdateGroupDryRunSecretsNeeded struct {
	ResourceID string `json:"resource_id,omitempty"`
	UserID     string `json:"user_id,omitempty"`
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
	err := checkUUIDFormat(groupID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
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
func (c *Client) UpdateGroup(ctx context.Context, groupID string, update GroupUpdate) (*Group, error) {
	err := checkUUIDFormat(groupID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequest(ctx, "PUT", "/groups/"+groupID+".json", "v2", update, nil)
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

// UpdateGroupDryRun Checks that a Passbolt Group update passes validation
func (c *Client) UpdateGroupDryRun(ctx context.Context, groupID string, update GroupUpdate) (*UpdateGroupDryRunResult, error) {
	err := checkUUIDFormat(groupID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequest(ctx, "PUT", "/groups/"+groupID+"/dry-run.json", "v2", update, nil)
	if err != nil {
		return nil, err
	}
	var result UpdateGroupDryRunResult
	err = json.Unmarshal(msg.Body, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteGroup Deletes a Passbolt Group
func (c *Client) DeleteGroup(ctx context.Context, groupID string) error {
	err := checkUUIDFormat(groupID)
	if err != nil {
		return fmt.Errorf("Checking ID format: %w", err)
	}
	_, err = c.DoCustomRequest(ctx, "DELETE", "/groups/"+groupID+".json", "v2", nil, nil)
	if err != nil {
		return err
	}
	return nil
}
