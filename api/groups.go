package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
	UserCount  int    `json:"user_count,omitempty"`
	// This does not Contain Profile for Users Anymore...
	GroupUsers []GroupMembership `json:"groups_users,omitempty"`
	// This is new and undocumented but as all the data
	Users []GroupUser `json:"users,omitempty"`
}

type GroupUser struct {
	User
	JoinData GroupJoinData `json:"_join_data,omitempty"`
}

// UnmarshalJSON accepts the join-data names used by supported server versions.
func (g *GroupUser) UnmarshalJSON(data []byte) error {
	var value struct {
		User
		Snake *GroupJoinData `json:"_join_data"`
		Camel *GroupJoinData `json:"_joinData"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	if value.Snake != nil && value.Camel != nil {
		a, b := value.Snake, value.Camel
		conflict := func(x, y string) bool { return x != "" && y != "" && !strings.EqualFold(x, y) }
		if conflict(a.ID, b.ID) || conflict(a.UserID, b.UserID) || conflict(a.GroupID, b.GroupID) || (a.HasRoleInformation() && b.HasRoleInformation() && a.IsAdmin != b.IsAdmin) {
			return fmt.Errorf("conflicting group join data")
		}
		if a.ID == "" {
			a.ID = b.ID
		}
		if a.UserID == "" {
			a.UserID = b.UserID
		}
		if a.GroupID == "" {
			a.GroupID = b.GroupID
		}
		if !a.HasRoleInformation() && b.HasRoleInformation() {
			a.IsAdmin = b.IsAdmin
			a.adminRoleKnown = true
		}
	}
	*g = GroupUser{User: value.User}
	if value.Snake != nil {
		g.JoinData = *value.Snake
	} else if value.Camel != nil {
		g.JoinData = *value.Camel
	}

	return nil
}

type GroupJoinData struct {
	adminRoleKnown bool
	ID             string `json:"id,omitempty"`
	GroupID        string `json:"group_id,omitempty"`
	UserID         string `json:"user_id,omitempty"`
	IsAdmin        bool   `json:"is_admin,omitempty"`
	Created        *Time  `json:"created,omitempty"`
}

type GroupMembership struct {
	adminRoleKnown bool
	ID             string `json:"id,omitempty"`
	UserID         string `json:"user_id,omitempty"`
	GroupID        string `json:"group_id,omitempty"`
	IsAdmin        bool   `json:"is_admin"`
	Delete         bool   `json:"delete,omitempty"`
	User           User   `json:"user,omitempty"`
	Created        *Time  `json:"created,omitempty"`
}

// HasRoleInformation reports whether the server supplied a non-null is_admin.
func (m GroupMembership) HasRoleInformation() bool { return m.adminRoleKnown }

// HasRoleInformation reports whether the server supplied a non-null is_admin.
func (m GroupJoinData) HasRoleInformation() bool { return m.adminRoleKnown }

func (m *GroupMembership) UnmarshalJSON(data []byte) error {
	type plain GroupMembership
	var value plain
	wire := struct {
		*plain
		IsAdmin *bool `json:"is_admin"`
	}{plain: &value}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*m = GroupMembership(value)
	m.adminRoleKnown = wire.IsAdmin != nil
	if wire.IsAdmin != nil {
		m.IsAdmin = *wire.IsAdmin
	}
	return nil
}

func (m *GroupJoinData) UnmarshalJSON(data []byte) error {
	type plain GroupJoinData
	var value plain
	wire := struct {
		*plain
		IsAdmin *bool `json:"is_admin"`
	}{plain: &value}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*m = GroupJoinData(value)
	m.adminRoleKnown = wire.IsAdmin != nil
	if wire.IsAdmin != nil {
		m.IsAdmin = *wire.IsAdmin
	}
	return nil
}

type GroupUpdate struct {
	Name         string            `json:"name,omitempty"`
	GroupChanges []GroupMembership `json:"groups_users,omitempty"`
	Secrets      []Secret          `json:"secrets,omitempty"`
}

// GetGroupsOptions are all available query parameters
type GetGroupsOptions struct {
	FilterHasUsers    []string `url:"filter[has-users][],omitempty"`
	FilterHasManagers []string `url:"filter[has-managers][],omitempty"`

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
	return doList[Group](ctx, c, "/groups.json", opts)
}

// CreateGroup Creates a new Passbolt Group
func (c *Client) CreateGroup(ctx context.Context, group Group) (*Group, error) {
	return doSave(ctx, c, "POST", "/groups.json", group)
}

// GetGroup gets a Passbolt Group
func (c *Client) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	return c.GetGroupWithOptions(ctx, groupID, nil)
}

// GetGroupWithOptions gets a group with explicitly requested associations.
func (c *Client) GetGroupWithOptions(ctx context.Context, groupID string, opts *GetGroupsOptions) (*Group, error) {
	if err := checkUUIDFormat(groupID); err != nil {
		return nil, fmt.Errorf("checking ID format: %w", err)
	}
	return doInto[Group](ctx, c, "GET", "/groups/"+groupID+".json", nil, opts)
}

// UpdateGroup Updates a existing Passbolt Group
func (c *Client) UpdateGroup(ctx context.Context, groupID string, update GroupUpdate) (*Group, error) {
	if err := checkUUIDFormat(groupID); err != nil {
		return nil, fmt.Errorf("checking ID format: %w", err)
	}
	return doInto[Group](ctx, c, "PUT", "/groups/"+groupID+".json", update, nil)
}

// UpdateGroupDryRun Checks that a Passbolt Group update passes validation
func (c *Client) UpdateGroupDryRun(ctx context.Context, groupID string, update GroupUpdate) (*UpdateGroupDryRunResult, error) {
	if err := checkUUIDFormat(groupID); err != nil {
		return nil, fmt.Errorf("checking ID format: %w", err)
	}
	return doInto[UpdateGroupDryRunResult](ctx, c, "PUT", "/groups/"+groupID+"/dry-run.json", update, nil)
}

// DeleteGroup Deletes a Passbolt Group
func (c *Client) DeleteGroup(ctx context.Context, groupID string) error {
	if err := checkUUIDFormat(groupID); err != nil {
		return fmt.Errorf("checking ID format: %w", err)
	}
	return doDelete(ctx, c, "/groups/"+groupID+".json")
}
