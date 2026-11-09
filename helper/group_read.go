package helper

import (
	"context"
	"fmt"
	"strings"

	"github.com/passbolt/go-passbolt/api"
)

// readGroupMemberships reads one group and normalizes the supported association
// layouts. Missing associations must not be mistaken for an empty group.
func readGroupMemberships(ctx context.Context, c *api.Client, groupID string) (*api.Group, []api.GroupMembership, error) {
	group, err := c.GetGroupWithOptions(ctx, groupID, &api.GetGroupsOptions{ContainUsers: true, ContainGroupsUsers: true, ContainGroupsUsersUser: true, ContainGroupsUsersUserProfile: true})
	if err != nil {
		return nil, nil, fmt.Errorf("getting group: %w", err)
	}
	if !strings.EqualFold(group.ID, groupID) {
		return nil, nil, fmt.Errorf("group response ID does not match requested group")
	}
	if group.GroupUsers == nil && group.Users == nil {
		return nil, nil, fmt.Errorf("group response has no membership associations")
	}
	members := make([]api.GroupMembership, 0, len(group.GroupUsers)+len(group.Users))
	indexes := make(map[string]int)
	knownRoles := make(map[string]bool)
	for _, m := range group.GroupUsers {
		if m.GroupID != "" && !strings.EqualFold(m.GroupID, groupID) {
			return nil, nil, fmt.Errorf("group membership group ID mismatch")
		}
		if m.UserID != "" && m.User.ID != "" && !strings.EqualFold(m.UserID, m.User.ID) {
			return nil, nil, fmt.Errorf("group membership nested user ID mismatch")
		}

		if m.UserID == "" {
			m.UserID = m.User.ID
		}
		if m.UserID == "" {
			return nil, nil, fmt.Errorf("group membership has no user ID")
		}
		m.UserID = strings.ToLower(m.UserID)
		if _, ok := indexes[m.UserID]; ok {
			return nil, nil, fmt.Errorf("duplicate group membership for user %s", m.UserID)
		}
		knownRoles[m.UserID] = m.HasRoleInformation()
		indexes[m.UserID] = len(members)
		members = append(members, m)
	}
	for _, u := range group.Users {
		if u.ID == "" {
			return nil, nil, fmt.Errorf("group user has no user ID")
		}
		u.ID = strings.ToLower(u.ID)
		if u.JoinData.GroupID != "" && !strings.EqualFold(u.JoinData.GroupID, groupID) {
			return nil, nil, fmt.Errorf("group join data group ID mismatch")
		}
		if u.JoinData.UserID != "" && !strings.EqualFold(u.JoinData.UserID, u.ID) {
			return nil, nil, fmt.Errorf("group join data user ID mismatch")
		}
		if index, ok := indexes[u.ID]; ok {
			m := &members[index]

			if m.ID != "" && u.JoinData.ID != "" && !strings.EqualFold(m.ID, u.JoinData.ID) {
				return nil, nil, fmt.Errorf("conflicting membership IDs for user %s", u.ID)
			}
			if u.JoinData.HasRoleInformation() {
				if knownRoles[u.ID] && m.IsAdmin != u.JoinData.IsAdmin {
					return nil, nil, fmt.Errorf("conflicting membership roles for user %s", u.ID)
				}
				m.IsAdmin = u.JoinData.IsAdmin
				knownRoles[u.ID] = true
			}
			if m.ID == "" {
				m.ID = u.JoinData.ID
			}

			if u.Username != "" {
				m.User.Username = u.Username
			}
			if u.Profile != nil {
				m.User.Profile = u.Profile
			}
		} else {
			if u.JoinData.ID == "" {
				return nil, nil, fmt.Errorf("group user %s has no join data", u.ID)
			}
			knownRoles[u.ID] = u.JoinData.HasRoleInformation()
			indexes[u.ID] = len(members)
			members = append(members, api.GroupMembership{ID: u.JoinData.ID, UserID: u.ID, GroupID: groupID, IsAdmin: u.JoinData.IsAdmin, User: u.User})
		}
	}
	for _, m := range members {
		if m.ID == "" {
			return nil, nil, fmt.Errorf("missing membership ID for user %s", m.UserID)
		}
		if !knownRoles[m.UserID] {
			return nil, nil, fmt.Errorf("missing membership role for user %s", m.UserID)
		}
	}
	return group, members, nil
}
