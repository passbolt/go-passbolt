package helper

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/passbolt/go-passbolt/api"
)

// UpdateResource Updates all Fields.
// Note if you want to Change the FolderParentID please use the MoveResource Function
func UpdateResource(ctx context.Context, c *api.Client, resourceID, name, username, uri, password, description string) error {
	resource, err := c.GetResource(ctx, resourceID)
	if err != nil {
		return fmt.Errorf("Getting Resource: %w", err)
	}

	rType, err := c.GetResourceType(ctx, resource.ResourceTypeID)
	if err != nil {
		return fmt.Errorf("Getting ResourceType: %w", err)
	}

	opts := &api.GetUsersOptions{
		FilterHasAccess: []string{resourceID},
	}
	users, err := c.GetUsers(ctx, opts)
	if err != nil {
		return fmt.Errorf("Getting Users: %w", err)
	}

	newResource := api.Resource{
		ID: resourceID,
		// This needs to be specified or it will revert to a legacy password
		ResourceTypeID: resource.ResourceTypeID,
	}
	var secretData string

	// Check if this is a v5 or Later Resource
	if resource.Metadata != "" {
		// Get Metadata
		orgMetadata, err := GetResourceMetadata(ctx, c, resource, rType)
		if err != nil {
			return fmt.Errorf("Get Resource metadata: %w", err)
		}

		var metadataMap map[string]any
		err = json.Unmarshal([]byte(orgMetadata), &metadataMap)
		if err != nil {
			return fmt.Errorf("Marshalling metadata: %w", err)
		}

		var newMetadata []byte
		switch rType.Slug {
		case "v5-default":
			// Modify Metadata
			if name != "" {
				metadataMap["name"] = name
			}
			if username != "" {
				metadataMap["username"] = username
			}
			if uri != "" {
				metadataMap["uris"] = []string{uri}
			}
		case "v5-password-string":
			// Modify Metadata
			if name != "" {
				metadataMap["name"] = name
			}
			if username != "" {
				metadataMap["username"] = username
			}
			if uri != "" {
				metadataMap["uris"] = []string{uri}
			}
			if description != "" {
				metadataMap["description"] = description
			}
		case "v5-default-with-totp":
			// Modify Metadata
			if name != "" {
				metadataMap["name"] = name
			}
			if username != "" {
				metadataMap["username"] = username
			}
			if uri != "" {
				metadataMap["uris"] = []string{uri}
			}
		case "v5-totp-standalone":
			// Modify Metadata
			if name != "" {
				metadataMap["name"] = name
			}
			if uri != "" {
				metadataMap["uris"] = []string{uri}
			}
		default:
			return fmt.Errorf("Unknown ResourceType: %v", rType.Slug)
		}

		newMetadata, err = json.Marshal(&metadataMap)
		if err != nil {
			return fmt.Errorf("Marshalling metadata: %w", err)
		}

		// Validate Metadata
		err = validateMetadata(rType, string(newMetadata))
		if err != nil {
			return fmt.Errorf("Validating metadata: %w", err)
		}

		metadataKeyID, metadataKeyType, publicMetadataKey, err := GetMetadataKey(ctx, c, true)
		if err != nil {
			return fmt.Errorf("Get Metadata Key: %w", err)
		}
		newResource.MetadataKeyID = metadataKeyID
		newResource.MetadataKeyType = metadataKeyType

		encMetadata, err := c.EncryptMessageWithKey(publicMetadataKey, string(newMetadata))
		if err != nil {
			return fmt.Errorf("Encrypt Metadata: %w", err)
		}
		newResource.Metadata = encMetadata

		// Modify Secret
		switch rType.Slug {
		case "v5-default":
			tmp := api.SecretDataTypeV5Default{
				Password:    password,
				Description: description,
			}
			tmp.ObjectType = api.PASSBOLT_OBJECT_TYPE_SECRET_DATA
			tmp.ResourceTypeID = rType.ID
			if password != "" || description != "" {
				secret, err := c.GetSecret(ctx, resourceID)
				if err != nil {
					return fmt.Errorf("Getting Secret: %w", err)
				}
				oldSecretData, err := c.DecryptMessage(secret.Data)
				if err != nil {
					return fmt.Errorf("Decrypting Secret: %w", err)
				}
				var oldSecret api.SecretDataTypeV5Default
				err = json.Unmarshal([]byte(oldSecretData), &oldSecret)
				if err != nil {
					return fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
				}
				if password == "" {
					tmp.Password = oldSecret.Password
				}
				if description == "" {
					tmp.Description = oldSecret.Description
				}
			}
			res, err := json.Marshal(&tmp)
			if err != nil {
				return fmt.Errorf("Marshalling Secret Data: %w", err)
			}
			secretData = string(res)
		case "v5-password-string":
			newResource.Description = resource.Description
			if description != "" {
				newResource.Description = description
			}
			if password != "" {
				secretData = password
			} else {
				secret, err := c.GetSecret(ctx, resourceID)
				if err != nil {
					return fmt.Errorf("Getting Secret: %w", err)
				}
				secretData, err = c.DecryptMessage(secret.Data)
				if err != nil {
					return fmt.Errorf("Decrypting Secret: %w", err)
				}
			}
		case "v5-default-with-totp":
			secret, err := c.GetSecret(ctx, resourceID)
			if err != nil {
				return fmt.Errorf("Getting Secret: %w", err)
			}
			oldSecretData, err := c.DecryptMessage(secret.Data)
			if err != nil {
				return fmt.Errorf("Decrypting Secret: %w", err)
			}
			var oldSecret api.SecretDataTypeV5DefaultWithTOTP
			err = json.Unmarshal([]byte(oldSecretData), &secretData)
			if err != nil {
				return fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
			}
			if password != "" {
				oldSecret.Password = password
			}
			if description != "" {
				oldSecret.Description = description
			}

			res, err := json.Marshal(&oldSecret)
			if err != nil {
				return fmt.Errorf("Marshalling Secret Data: %w", err)
			}
			secretData = string(res)
		case "v5-totp-standalone":
			secret, err := c.GetSecret(ctx, resourceID)
			if err != nil {
				return fmt.Errorf("Getting Secret: %w", err)
			}
			oldSecretData, err := c.DecryptMessage(secret.Data)
			if err != nil {
				return fmt.Errorf("Decrypting Secret: %w", err)
			}
			var oldSecret api.SecretDataTypeTOTP
			err = json.Unmarshal([]byte(oldSecretData), &secretData)
			if err != nil {
				return fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
			}
			// since we don't have totp parameters we don't do anything

			res, err := json.Marshal(&oldSecret)
			if err != nil {
				return fmt.Errorf("Marshalling Secret Data: %w", err)
			}
			secretData = string(res)
		default:
			return fmt.Errorf("Unknown ResourceType: %v", rType.Slug)
		}
	} else {
		// V4 Resource
		newResource.Name = resource.Name
		newResource.Username = resource.Username
		newResource.URI = resource.URI

		if name != "" {
			newResource.Name = name
		}
		if username != "" {
			newResource.Username = username
		}
		if uri != "" {
			newResource.URI = uri
		}

		// Secret
		switch rType.Slug {
		case "password-string":
			newResource.Description = resource.Description
			if description != "" {
				newResource.Description = description
			}
			if password != "" {
				secretData = password
			} else {
				secret, err := c.GetSecret(ctx, resourceID)
				if err != nil {
					return fmt.Errorf("Getting Secret: %w", err)
				}
				secretData, err = c.DecryptMessage(secret.Data)
				if err != nil {
					return fmt.Errorf("Decrypting Secret: %w", err)
				}
			}
		case "password-and-description":
			tmp := api.SecretDataTypePasswordAndDescription{
				Password:    password,
				Description: description,
			}
			if password != "" || description != "" {
				secret, err := c.GetSecret(ctx, resourceID)
				if err != nil {
					return fmt.Errorf("Getting Secret: %w", err)
				}
				oldSecretData, err := c.DecryptMessage(secret.Data)
				if err != nil {
					return fmt.Errorf("Decrypting Secret: %w", err)
				}
				var oldSecret api.SecretDataTypePasswordAndDescription
				err = json.Unmarshal([]byte(oldSecretData), &oldSecret)
				if err != nil {
					return fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
				}
				if password == "" {
					tmp.Password = oldSecret.Password
				}
				if description == "" {
					tmp.Description = oldSecret.Description
				}
			}
			res, err := json.Marshal(&tmp)
			if err != nil {
				return fmt.Errorf("Marshalling Secret Data: %w", err)
			}
			secretData = string(res)
		case "password-description-totp":
			secret, err := c.GetSecret(ctx, resourceID)
			if err != nil {
				return fmt.Errorf("Getting Secret: %w", err)
			}
			oldSecretData, err := c.DecryptMessage(secret.Data)
			if err != nil {
				return fmt.Errorf("Decrypting Secret: %w", err)
			}
			var oldSecret api.SecretDataTypePasswordDescriptionTOTP
			err = json.Unmarshal([]byte(oldSecretData), &secretData)
			if err != nil {
				return fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
			}
			if password != "" {
				oldSecret.Password = password
			}
			if description != "" {
				oldSecret.Description = description
			}

			res, err := json.Marshal(&oldSecret)
			if err != nil {
				return fmt.Errorf("Marshalling Secret Data: %w", err)
			}
			secretData = string(res)
		case "totp":
			secret, err := c.GetSecret(ctx, resourceID)
			if err != nil {
				return fmt.Errorf("Getting Secret: %w", err)
			}
			oldSecretData, err := c.DecryptMessage(secret.Data)
			if err != nil {
				return fmt.Errorf("Decrypting Secret: %w", err)
			}
			var oldSecret api.SecretDataTypeTOTP
			err = json.Unmarshal([]byte(oldSecretData), &secretData)
			if err != nil {
				return fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
			}
			// since we don't have totp parameters we don't do anything

			res, err := json.Marshal(&oldSecret)
			if err != nil {
				return fmt.Errorf("Marshalling Secret Data: %w", err)
			}
			secretData = string(res)
		default:
			return fmt.Errorf("Unknown ResourceType: %v", rType.Slug)
		}
	}

	err = validateSecretData(rType, secretData)
	if err != nil {
		return fmt.Errorf("Validating Secret Data: %w", err)
	}

	newResource.Secrets = []api.Secret{}
	for _, user := range users {
		var encSecretData string
		// if this is our user use our stored and verified public key instead
		if user.ID == c.GetUserID() {
			encSecretData, err = c.EncryptMessage(secretData)
			if err != nil {
				return fmt.Errorf("Encrypting Secret Data for User me: %w", err)
			}
		} else {
			publicKey, err := crypto.NewKeyFromArmored(user.GPGKey.ArmoredKey)
			if err != nil {
				return fmt.Errorf("Get Public Key: %w", err)
			}

			encSecretData, err = c.EncryptMessageWithKey(publicKey, secretData)
			if err != nil {
				return fmt.Errorf("Encrypting Secret Data for User %v: %w", user.ID, err)
			}
		}
		newResource.Secrets = append(newResource.Secrets, api.Secret{
			UserID: user.ID,
			Data:   encSecretData,
		})
	}

	_, err = c.UpdateResource(ctx, resourceID, newResource)
	if err != nil {
		return fmt.Errorf("Updating Resource: %w", err)
	}
	return nil
}
