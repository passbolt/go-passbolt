package helper

import (
	"context"
	"fmt"

	"github.com/speatzle/go-passbolt/api"
)

// GroupMembershipOperation creates/modifies/deletes a group membership
type GroupMembershipOperation struct {
	UserID         string
	IsGroupManager bool
	Delete         bool
}

// GroupMembership containes who and what kind of membership they have with a group
type GroupMembership struct {
	UserID         string
	Username       string
	UserFirstName  string
	UserLastName   string
	IsGroupManager bool
}

// CreateGroup creates a Groups with Name and Memberships
func CreateGroup(ctx context.Context, c *api.Client, name string, operations []GroupMembershipOperation) (string, error) {
	memberships := []api.GroupMembership{}
	for _, o := range operations {
		if o.Delete {
			return "", fmt.Errorf("Cannot Delete Membership during Group Creation")
		}
		memberships = append(memberships, api.GroupMembership{
			UserID:  o.UserID,
			IsAdmin: o.IsGroupManager,
		})
	}
	group, err := c.CreateGroup(ctx, api.Group{
		Name:       name,
		GroupUsers: memberships,
	})
	if err != nil {
		return "", fmt.Errorf("Creating Group: %w", err)
	}
	return group.ID, nil
}

// GetGroup gets a Groups Name and Memberships
func GetGroup(ctx context.Context, c *api.Client, groupID string) (string, []GroupMembership, error) {
	// for some reason the groups index api call does not give back the groups_users even though it is supposed to, so i have to do this...
	groups, err := c.GetGroups(ctx, &api.GetGroupsOptions{
		ContainGroupUser: true,
	})
	if err != nil {
		return "", nil, fmt.Errorf("Getting Groups: %w", err)
	}

	for _, g := range groups {
		if g.ID == groupID {
			memberships := []GroupMembership{}
			for _, m := range g.GroupUsers {
				memberships = append(memberships, GroupMembership{
					UserID:         m.UserID,
					Username:       m.User.Username,
					UserFirstName:  m.User.Profile.FirstName,
					UserLastName:   m.User.Profile.LastName,
					IsGroupManager: m.IsAdmin,
				})
			}
			return g.Name, memberships, nil
		}
	}
	return "", nil, fmt.Errorf("Cannot Find Group in API Response")
}

// UpdateGroup Updates a Groups Name and Memberships
func UpdateGroup(ctx context.Context, c *api.Client, groupID, name string, operations []GroupMembershipOperation) error {
	// for some reason the groups index api call does not give back the groups_users even though it is supposed to, so i have to do this...
	groups, err := c.GetGroups(ctx, &api.GetGroupsOptions{
		ContainGroupUser: true,
	})
	if err != nil {
		return fmt.Errorf("Getting Groups: %w", err)
	}

	var currentMemberships []api.GroupMembership
	for _, g := range groups {
		if g.ID == groupID {
			currentMemberships = g.GroupUsers
			break
		}
	}
	if currentMemberships == nil {
		return fmt.Errorf("Cannot Find Group with ID %v", groupID)
	}

	request := api.GroupUpdate{
		Name:         name,
		GroupChanges: []api.GroupMembership{},
		Secrets:      []api.Secret{},
	}

	// Generate Group Membership changes based on current Group Memberships
	for _, operation := range operations {
		membership, err := getMembershipByUserID(currentMemberships, operation.UserID)
		if err != nil {
			// Membership does not Exist so we can only create a new one
			if operation.Delete {
				return fmt.Errorf("Cannot Delete User %v as it has no membership", operation.UserID)
			}
			request.GroupChanges = append(request.GroupChanges, api.GroupMembership{
				UserID:  operation.UserID,
				IsAdmin: operation.IsGroupManager,
			})
		} else {
			// Membership Exists so we can modify or delete it
			request.GroupChanges = append(request.GroupChanges, api.GroupMembership{
				ID:      membership.ID,
				IsAdmin: operation.IsGroupManager,
				Delete:  operation.Delete,
			})
		}
	}

	dryrun, err := c.UpdateGroupDryRun(ctx, groupID, request)
	if err != nil {
		return fmt.Errorf("Update Group Dryrun: %w", err)
	}

	var users []api.User
	// We can skip Getting users if we don't need to reencrypt any secrets
	if len(dryrun.DryRun.SecretsNeeded) != 0 {
		users, err = c.GetUsers(ctx, &api.GetUsersOptions{})
		if err != nil {
			return fmt.Errorf("Getting Users: %w", err)
		}
	}

	// The API gives it back nested so we just put it into a list here
	secrets := []api.Secret{}
	for _, container := range dryrun.DryRun.Secrets {
		secrets = append(secrets, container.Secret...)
	}

	decryptedSecretCache := map[string]string{}
	for _, container := range dryrun.DryRun.SecretsNeeded {
		missingSecret := container.Secret
		// Deduplicate Secret Decrypting for when adding multiple users to a group
		if decryptedSecretCache[missingSecret.ResourceID] == "" {
			secret, err := getSecretByResourceID(secrets, missingSecret.ResourceID)
			if err != nil {
				return fmt.Errorf("Get Secret from Dryrun Response: %w", err)
			}

			msg, err := c.DecryptMessage(secret.Data)
			if err != nil {
				return fmt.Errorf("Decrypting Secret: %w", err)
			}

			decryptedSecretCache[missingSecret.ResourceID] = msg
		}

		pubkey, err := getPublicKeyByUserID(missingSecret.UserID, users)
		if err != nil {
			return fmt.Errorf("Get pubkey for User: %w", err)
		}

		newSecretData, err := c.EncryptMessageWithPublicKey(pubkey, decryptedSecretCache[missingSecret.ResourceID])
		if err != nil {
			return fmt.Errorf("Encrypting Secret: %w", err)
		}
		request.Secrets = append(request.Secrets, api.Secret{
			UserID:     missingSecret.UserID,
			ResourceID: missingSecret.ResourceID,
			Data:       newSecretData,
		})
	}

	_, err = c.UpdateGroup(ctx, groupID, request)
	if err != nil {
		return fmt.Errorf("Updating Group: %w", err)
	}
	return nil
}

// DeleteGroup Deletes a Group
func DeleteGroup(ctx context.Context, c *api.Client, groupID string) error {
	err := c.DeleteGroup(ctx, groupID)
	if err != nil {
		return fmt.Errorf("Deleting Group: %w", err)
	}
	return nil
}
