package helper

import (
	"context"
	"fmt"

	"github.com/speatzle/go-passbolt/api"
)

// ShareOperation defines how Resources are to be Shared With Users/Groups
type ShareOperation struct {
	// Type of Permission: 1 = Read, 7 = can Update, 15 = Owner (Owner can also Share Resource)
	// Note: Setting this to -1 Will delete this Permission if it already Exists, errors if this Permission Dosen't Already Exists
	Type int
	// ARO is what Type this should be Shared With (User, Group)
	ARO string
	// AROID is the ID of the User or Group(ARO) this should be Shared With
	AROID string
}

// ShareResourceWithUsersAndGroups Shares a Resource With The Users and Groups with the Specified Permission Type,
// if the Resource has already been shared With the User/Group the Permission Type will be Adjusted/Deleted
func ShareResourceWithUsersAndGroups(ctx context.Context, c *api.Client, resourceID string, Users []string, Groups []string, permissionType int) error {
	changes := []ShareOperation{}
	for _, userID := range Users {
		changes = append(changes, ShareOperation{
			Type:  permissionType,
			ARO:   "User",
			AROID: userID,
		})
	}
	for _, groupID := range Groups {
		changes = append(changes, ShareOperation{
			Type:  permissionType,
			ARO:   "Group",
			AROID: groupID,
		})
	}
	return ShareResource(ctx, c, resourceID, changes)
}

// ShareResource Shares a Resource as Specified in the Passed ShareOperation Struct Slice
func ShareResource(ctx context.Context, c *api.Client, resourceID string, changes []ShareOperation) error {
	oldPermissions, err := c.GetResourcePermissions(ctx, resourceID)
	if err != nil {
		return fmt.Errorf("Getting Resource Permissions: %w", err)
	}

	permissionChanges, err := GeneratePermissionChanges(oldPermissions, changes)
	if err != nil {
		return fmt.Errorf("Generating Resource Permission Changes: %w", err)
	}

	shareRequest := api.ResourceShareRequest{Permissions: permissionChanges}

	secret, err := c.GetSecret(ctx, resourceID)
	if err != nil {
		return fmt.Errorf("Get Resource: %w", err)
	}

	secretData, err := c.DecryptMessage(secret.Data)
	if err != nil {
		return fmt.Errorf("Decrypting Resource Secret: %w", err)
	}

	simulationResult, err := c.SimulateShareResource(ctx, resourceID, shareRequest)
	if err != nil {
		return fmt.Errorf("Simulate Share Resource: %w", err)
	}

	// if no users where added then we can skip this
	var users []api.User
	if len(simulationResult.Changes.Added) != 0 {
		users, err = c.GetUsers(ctx, nil)
		if err != nil {
			return fmt.Errorf("Get Users: %w", err)
		}
	}

	shareRequest.Secrets = []api.Secret{}
	for _, user := range simulationResult.Changes.Added {
		pubkey, err := getPublicKeyByUserID(user.User.ID, users)
		if err != nil {
			return fmt.Errorf("Getting Public Key for User %v: %w", user.User.ID, err)
		}

		encSecretData, err := c.EncryptMessageWithPublicKey(pubkey, secretData)
		if err != nil {
			return fmt.Errorf("Encrypting Secret for User %v: %w", user.User.ID, err)
		}
		shareRequest.Secrets = append(shareRequest.Secrets, api.Secret{
			UserID: user.User.ID,
			Data:   encSecretData,
		})
	}

	err = c.ShareResource(ctx, resourceID, shareRequest)
	if err != nil {
		return fmt.Errorf("Sharing Resource: %w", err)
	}
	return nil
}

// ShareFolderWithUsersAndGroups Shares a Folder With The Users and Groups with the Specified Type,
// if the Folder has already been shared With the User/Group the Permission Type will be Adjusted/Deleted.
// Note: Resources Permissions in the Folder are not Adjusted (Like the Extension does)
func ShareFolderWithUsersAndGroups(ctx context.Context, c *api.Client, folderID string, Users []string, Groups []string, permissionType int) error {
	changes := []ShareOperation{}
	for _, userID := range Users {
		changes = append(changes, ShareOperation{
			Type:  permissionType,
			ARO:   "User",
			AROID: userID,
		})
	}
	for _, groupID := range Groups {
		changes = append(changes, ShareOperation{
			Type:  permissionType,
			ARO:   "Group",
			AROID: groupID,
		})
	}
	return ShareFolder(ctx, c, folderID, changes)
}

// ShareFolder Shares a Folder as Specified in the Passed ShareOperation Struct Slice.
// Note Resources Permissions in the Folder are not Adjusted
func ShareFolder(ctx context.Context, c *api.Client, folderID string, changes []ShareOperation) error {
	oldFolder, err := c.GetFolder(ctx, folderID, &api.GetFolderOptions{
		ContainPermissions: true,
	})
	if err != nil {
		return fmt.Errorf("Getting Folder Permissions: %w", err)
	}

	permissionChanges, err := GeneratePermissionChanges(oldFolder.Permissions, changes)
	if err != nil {
		return fmt.Errorf("Generating Folder Permission Changes: %w", err)
	}

	err = c.ShareFolder(ctx, folderID, permissionChanges)
	if err != nil {
		return fmt.Errorf("Sharing Folder: %w", err)
	}
	return nil
}

// GeneratePermissionChanges Generates the Permission Changes for a Resource/Folder nessesary for a single Share Operation
func GeneratePermissionChanges(oldPermissions []api.Permission, changes []ShareOperation) ([]api.Permission, error) {
	// Check for Duplicate Users/Groups as that would break stuff
	for i, changeA := range changes {
		for j, changeB := range changes {
			if i != j && changeA.AROID == changeB.AROID && changeA.ARO == changeB.ARO {
				return nil, fmt.Errorf("Change %v and %v are Both About the same ARO %v ID: %v, there can only be once change per ARO", i, j, changeA.ARO, changeA.AROID)
			}
		}
	}

	// Get ACO and ACO ID from Existing Permissions
	if len(oldPermissions) == 0 {
		return nil, fmt.Errorf("There has to be atleast one Permission on a ACO")
	}
	ACO := oldPermissions[0].ACO
	ACOID := oldPermissions[0].ACOForeignKey

	permissionChanges := []api.Permission{}
	for _, change := range changes {
		// Find Permission thats involves the Same ARO as Requested in the change
		var oldPermission *api.Permission
		for _, oldPerm := range oldPermissions {
			if oldPerm.ARO == change.ARO && oldPerm.AROForeignKey == change.AROID {
				oldPermission = &oldPerm
				break
			}
		}
		// Check Whether Matching Permission Already Exists and needs to be adjusted or is a new one can be created
		if oldPermission == nil {
			if change.Type == 15 || change.Type == 7 || change.Type == 1 {
				permissionChanges = append(permissionChanges, api.Permission{
					IsNew:         true,
					Type:          change.Type,
					ARO:           change.ARO,
					AROForeignKey: change.AROID,
					ACO:           ACO,
					ACOForeignKey: ACOID,
				})
			} else if change.Type == -1 {
				return nil, fmt.Errorf("Permission for %v %v Cannot be Deleted as No Matching Permission Exists", change.ARO, change.AROID)
			} else {
				return nil, fmt.Errorf("Unknown Permission Type: %v", change.Type)
			}
		} else {
			tmp := api.Permission{
				ID:            oldPermission.ID,
				ARO:           change.ARO,
				AROForeignKey: change.AROID,
				ACO:           ACO,
				ACOForeignKey: ACOID,
			}

			if change.Type == 15 || change.Type == 7 || change.Type == 1 {
				if oldPermission.Type == change.Type {
					return nil, fmt.Errorf("Permission for %v %v is already Type %v", change.ARO, change.AROID, change.Type)
				}
				tmp.Type = change.Type
			} else if change.Type == -1 {
				tmp.Delete = true
				tmp.Type = oldPermission.Type
			} else {
				return nil, fmt.Errorf("Unknown Permission Type: %v", change.Type)
			}
			permissionChanges = append(permissionChanges, tmp)
		}
	}
	return permissionChanges, nil
}
