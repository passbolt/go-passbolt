package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/passbolt/go-passbolt/api"
)

// UpdateResource updates resource fields. Empty strings are not applied (partial update).
// Note: to change FolderParentID, use MoveResource instead.
func UpdateResource(ctx context.Context, c *api.Client, resourceID, name, username, uri, password, description string) error {
	resource, err := c.GetResource(ctx, resourceID)
	if err != nil {
		return fmt.Errorf("getting resource: %w", err)
	}

	isV5 := resource.Metadata != ""

	// Build metadata updates
	metadataUpdates := map[string]any{}
	if name != "" {
		metadataUpdates["name"] = name
	}
	if username != "" {
		metadataUpdates["username"] = username
	}
	if uri != "" {
		if isV5 {
			metadataUpdates["uris"] = []string{uri}
		} else {
			metadataUpdates["uri"] = uri
		}
	}
	// Put description in metadata; routeFieldBySchema in UpdateResourceGeneric
	// will move it to secret if the schema requires it.
	if description != "" {
		metadataUpdates["description"] = description
	}

	// Build secret updates
	secretUpdates := map[string]any{}
	if password != "" {
		secretUpdates["password"] = password
	}

	return UpdateResourceGeneric(ctx, c, resourceID, metadataUpdates, secretUpdates)
}

// UpdateResourceGeneric updates a resource using dynamic field maps.
// Only provided keys are updated; existing values are preserved for keys not in the update maps.
func UpdateResourceGeneric(ctx context.Context, c *api.Client, resourceID string, metadataUpdates map[string]any, secretUpdates map[string]any) error {
	resource, err := c.GetResource(ctx, resourceID)
	if err != nil {
		return fmt.Errorf("getting resource: %w", err)
	}

	rType, err := c.GetResourceType(ctx, resource.ResourceTypeID)
	if err != nil {
		return fmt.Errorf("getting resource type: %w", err)
	}

	opts := &api.GetUsersOptions{
		FilterHasAccess: []string{resourceID},
	}
	users, err := c.GetUsers(ctx, opts)
	if err != nil {
		return fmt.Errorf("getting users: %w", err)
	}

	isV5 := resource.Metadata != ""

	// Auto-route fields between metadata and secret based on schema
	routeFieldBySchema(rType, metadataUpdates, secretUpdates, "description")

	newResource := api.Resource{
		ID:             resourceID,
		ResourceTypeID: resource.ResourceTypeID,
	}

	// --- Handle metadata ---
	if isV5 {
		// V5: decrypt existing metadata, merge updates, re-encrypt
		orgMetadata, err := GetResourceMetadata(ctx, c, resource, rType)
		if err != nil {
			return fmt.Errorf("getting resource metadata: %w", err)
		}

		var metadataMap map[string]any
		err = json.Unmarshal([]byte(orgMetadata), &metadataMap)
		if err != nil {
			return fmt.Errorf("parsing metadata: %w", err)
		}

		// Merge updates
		for k, v := range metadataUpdates {
			metadataMap[k] = v
		}

		newMetadata, err := json.Marshal(metadataMap)
		if err != nil {
			return fmt.Errorf("marshaling metadata: %w", err)
		}

		err = validateMetadata(rType, string(newMetadata))
		if err != nil {
			return fmt.Errorf("validating metadata: %w", err)
		}

		personal := resource.MetadataKeyType != api.MetadataKeyTypeSharedKey
		metadataKeyID, metadataKeyType, publicMetadataKey, err := c.GetMetadataKey(ctx, personal)
		if err != nil {
			return fmt.Errorf("get metadata key: %w", err)
		}
		newResource.MetadataKeyID = metadataKeyID
		newResource.MetadataKeyType = metadataKeyType

		encMetadata, err := c.EncryptMessageWithKey(publicMetadataKey, string(newMetadata))
		if err != nil {
			return fmt.Errorf("encrypt metadata: %w", err)
		}
		newResource.Metadata = encMetadata
	} else {
		// V4: set cleartext fields, preserving existing values
		newResource.Name = resource.Name
		newResource.Username = resource.Username
		newResource.URI = resource.URI
		newResource.Description = resource.Description

		if v := getStringFromMap(metadataUpdates, "name"); v != "" {
			newResource.Name = v
		}
		if v := getStringFromMap(metadataUpdates, "username"); v != "" {
			newResource.Username = v
		}
		if v := getStringFromMap(metadataUpdates, "uri"); v != "" {
			newResource.URI = v
		}
		if v := getStringFromMap(metadataUpdates, "description"); v != "" {
			newResource.Description = v
		}
	}

	// --- Handle secret ---
	var secretDataStr string

	if rType.IsSecretString() {
		// Secret is a plain string (password)
		if pw := getStringFromMap(secretUpdates, "password"); pw != "" {
			secretDataStr = pw
		} else {
			// Preserve existing secret
			secret, err := c.GetSecret(ctx, resourceID)
			if err != nil {
				return fmt.Errorf("getting secret: %w", err)
			}
			secretDataStr, err = c.DecryptMessage(secret.Data)
			if err != nil {
				return fmt.Errorf("decrypting secret: %w", err)
			}
		}
	} else {
		// Secret is JSON - fetch existing, merge updates
		secret, err := c.GetSecret(ctx, resourceID)
		if err != nil {
			return fmt.Errorf("getting secret: %w", err)
		}
		oldSecretData, err := c.DecryptMessage(secret.Data)
		if err != nil {
			return fmt.Errorf("decrypting secret: %w", err)
		}

		var secretMap map[string]any
		err = json.Unmarshal([]byte(oldSecretData), &secretMap)
		if err != nil {
			return fmt.Errorf("parsing decrypted secret data: %w", err)
		}

		// Merge updates
		for k, v := range secretUpdates {
			secretMap[k] = v
		}

		res, err := json.Marshal(secretMap)
		if err != nil {
			return fmt.Errorf("marshaling secret data: %w", err)
		}
		secretDataStr = string(res)
	}

	err = validateSecretData(rType, secretDataStr)
	if err != nil {
		return fmt.Errorf("validating secret data: %w", err)
	}

	// Encrypt secret for all users with access
	newResource.Secrets = []api.Secret{}
	for _, user := range users {
		var encSecretData string
		if user.ID == c.GetUserID() {
			encSecretData, err = c.EncryptMessage(secretDataStr)
			if err != nil {
				return fmt.Errorf("encrypting secret data for user me: %w", err)
			}
		} else {
			publicKey, err := crypto.NewKeyFromArmored(user.GPGKey.ArmoredKey)
			if err != nil {
				return fmt.Errorf("get public key: %w", err)
			}

			encSecretData, err = c.EncryptMessageWithKey(publicKey, secretDataStr)
			if err != nil {
				return fmt.Errorf("encrypting secret data for user %v: %w", user.ID, err)
			}
		}
		newResource.Secrets = append(newResource.Secrets, api.Secret{
			UserID: user.ID,
			Data:   encSecretData,
		})
	}

	// Handle password expiry
	passwordExpirySettings := c.GetPasswordExpirySettings()
	if resource.Expired != nil && passwordExpirySettings.AutomaticUpdate {
		expiry := time.Now().Add(time.Hour * 24 * time.Duration(passwordExpirySettings.DefaultExpiryPeriod))
		newResource.Expired = &api.Time{Time: expiry}
	}

	_, err = c.UpdateResource(ctx, resourceID, newResource)
	if err != nil {
		return fmt.Errorf("updating resource: %w", err)
	}
	return nil
}
