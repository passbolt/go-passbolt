package helper

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"strings"

	"github.com/passbolt/go-passbolt/api"
)

// GroupMembershipOperation creates/modifies/deletes a group membership
type GroupMembershipOperation struct {
	UserID         string
	IsGroupManager bool
	Delete         bool
}

// GroupMembership contains who and what kind of membership they have with a group
type GroupMembership struct {
	MembershipID   string
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
			return "", fmt.Errorf("cannot Delete Membership during Group Creation")
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
		return "", fmt.Errorf("creating Group: %w", err)
	}
	return group.ID, nil
}

// GetGroup gets a Groups Name and Memberships
func GetGroup(ctx context.Context, c *api.Client, groupID string) (string, []GroupMembership, error) {
	group, current, err := readGroupMemberships(ctx, c, groupID)
	if err != nil {
		return "", nil, err
	}
	memberships := make([]GroupMembership, 0, len(current))
	for _, m := range current {
		member := GroupMembership{MembershipID: m.ID, UserID: m.UserID, Username: m.User.Username, IsGroupManager: m.IsAdmin}
		if m.User.Profile != nil {
			member.UserFirstName, member.UserLastName = m.User.Profile.FirstName, m.User.Profile.LastName
		}
		memberships = append(memberships, member)
	}
	return group.Name, memberships, nil
}

// UpdateGroup Updates a Groups Name and Memberships
func UpdateGroup(ctx context.Context, c *api.Client, groupID, name string, operations []GroupMembershipOperation) error {
	unique := make([]GroupMembershipOperation, 0, len(operations))
	seen := make(map[string]GroupMembershipOperation)
	for _, op := range operations {
		if len(op.UserID) != 36 || uuid.Validate(op.UserID) != nil {
			return fmt.Errorf("invalid user ID %q", op.UserID)
		}
		op.UserID = strings.ToLower(op.UserID)
		if previous, ok := seen[op.UserID]; ok {
			if previous != op {
				return fmt.Errorf("conflicting operations for user %s", op.UserID)
			}
			continue
		}
		seen[op.UserID] = op
		unique = append(unique, op)
	}
	operations = unique
	group, currentMemberships, err := readGroupMemberships(ctx, c, groupID)
	if err != nil {
		return err
	}
	currentName := group.Name

	request := api.GroupUpdate{
		Name:         name,
		GroupChanges: []api.GroupMembership{},
		Secrets:      []api.Secret{},
	}

	if name == "" {
		request.Name = currentName
	}

	// Generate Group Membership changes based on current Group Memberships
	for _, operation := range operations {
		membership, err := getMembershipByUserID(currentMemberships, operation.UserID)
		if err != nil {
			// Membership does not Exist so we can only create a new one
			if operation.Delete {
				continue
			}
			request.GroupChanges = append(request.GroupChanges, api.GroupMembership{
				UserID:  operation.UserID,
				IsAdmin: operation.IsGroupManager,
			})
		} else {
			// Membership Exists so we can modify or delete it
			if membership.ID == "" {
				return fmt.Errorf("missing membership ID for user %s", operation.UserID)
			}
			if !operation.Delete && membership.IsAdmin == operation.IsGroupManager {
				continue
			}
			request.GroupChanges = append(request.GroupChanges, api.GroupMembership{
				ID:      membership.ID,
				IsAdmin: operation.IsGroupManager,
				Delete:  operation.Delete,
			})
		}
	}

	if len(request.GroupChanges) == 0 && request.Name == currentName {
		return nil
	}

	dryrun, err := c.UpdateGroupDryRun(ctx, groupID, request)
	if err != nil {
		return fmt.Errorf("update Group Dryrun: %w", err)
	}

	var users []api.User
	// We can skip Getting users if we don't need to reencrypt any secrets
	if len(dryrun.DryRun.SecretsNeeded) != 0 {
		users, err = c.GetUsers(ctx, &api.GetUsersOptions{})
		if err != nil {
			return fmt.Errorf("getting Users: %w", err)
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
				return fmt.Errorf("get Secret from Dryrun Response: %w", err)
			}

			msg, err := c.DecryptMessage(secret.Data)
			if err != nil {
				return fmt.Errorf("decrypting Secret: %w", err)
			}

			decryptedSecretCache[missingSecret.ResourceID] = msg
		}

		pubkey, err := getPublicKeyByUserID(missingSecret.UserID, users)
		if err != nil {
			return fmt.Errorf("get pubkey for User: %w", err)
		}

		newSecretData, err := encryptForArmoredKey(c, pubkey, decryptedSecretCache[missingSecret.ResourceID])
		if err != nil {
			return fmt.Errorf("encrypting Secret: %w", err)
		}
		request.Secrets = append(request.Secrets, api.Secret{
			UserID:     missingSecret.UserID,
			ResourceID: missingSecret.ResourceID,
			Data:       newSecretData,
		})
	}

	_, err = c.UpdateGroup(ctx, groupID, request)
	if err != nil {
		return fmt.Errorf("updating Group: %w", err)
	}
	verified, memberships, err := readGroupMemberships(ctx, c, groupID)
	if err != nil {
		return fmt.Errorf("verifying group update: %w", err)
	}
	if verified.Name != request.Name {
		return fmt.Errorf("verifying group update: name did not match requested value")
	}
	for _, op := range operations {
		membership, lookupErr := getMembershipByUserID(memberships, op.UserID)
		if op.Delete {
			if lookupErr == nil {
				return fmt.Errorf("verifying group update: user %s is still a member", op.UserID)
			}
		} else if lookupErr != nil || membership.IsAdmin != op.IsGroupManager {
			return fmt.Errorf("verifying group update: requested role missing for user %s", op.UserID)
		}
	}
	return nil
}

// DeleteGroup Deletes a Group
func DeleteGroup(ctx context.Context, c *api.Client, groupID string) error {
	err := c.DeleteGroup(ctx, groupID)
	if err != nil {
		return fmt.Errorf("deleting Group: %w", err)
	}
	return nil
}
