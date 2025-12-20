package helper

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/passbolt/go-passbolt/api"
)

// GetResource Gets a Resource by ID
func GetResource(ctx context.Context, c *api.Client, resourceID string) (folderParentID, name, username, uri, password, description string, err error) {
	resource, err := c.GetResource(ctx, resourceID)
	if err != nil {
		return "", "", "", "", "", "", fmt.Errorf("Getting Resource: %w", err)
	}

	rType, err := c.GetResourceType(ctx, resource.ResourceTypeID)
	if err != nil {
		return "", "", "", "", "", "", fmt.Errorf("Getting ResourceType: %w", err)
	}
	secret, err := c.GetSecret(ctx, resource.ID)
	if err != nil {
		return "", "", "", "", "", "", fmt.Errorf("Getting Resource Secret: %w", err)
	}
	return GetResourceFromData(c, *resource, *secret, *rType)
}

// GetResourceFromData Decrypts Resources using only local data, the Resource object must include the secret
// With v5 This needs network calls for Metadata of v5 Resources
func GetResourceFromData(c *api.Client, resource api.Resource, secret api.Secret, rType api.ResourceType) (string, string, string, string, string, string, error) {
	return GetResourceFromDataWithOptions(c, resource, secret, rType, true)
}

// GetResourceFromDataWithOptions Decrypts Resources with option to skip secret decryption.
// For v5 resources, metadata (name, username, uri) can be decrypted without the secret.
// Set decryptSecret=false to skip secret decryption (password/description will be empty).
// This provides significant performance improvement when only metadata is needed.
func GetResourceFromDataWithOptions(c *api.Client, resource api.Resource, secret api.Secret, rType api.ResourceType, decryptSecret bool) (string, string, string, string, string, string, error) {
	var name string
	var username string
	var uri string
	var pw string
	var desc string

	ctx := context.TODO()

	// For v5 resources, we can get metadata without decrypting the secret
	// For v4 resources, metadata is in cleartext on the resource object
	var rawSecretData string
	var err error

	if decryptSecret && secret.Data != "" {
		rawSecretData, err = c.DecryptSecretWithResourceID(resource.ID, secret.Data)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Decrypting Secret Data: %w", err)
		}

		err = validateSecretData(&rType, rawSecretData)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Validate Secret Data: %w", err)
		}
	}

	switch rType.Slug {
	case "password-string":
		pw = rawSecretData
		name = resource.Name
		username = resource.Username
		uri = resource.URI
		desc = resource.Description
	case "password-and-description":
		name = resource.Name
		username = resource.Username
		uri = resource.URI
		// Only parse secret data if it was decrypted
		if rawSecretData != "" {
			var secretData api.SecretDataTypePasswordAndDescription
			err = json.Unmarshal([]byte(rawSecretData), &secretData)
			if err != nil {
				return "", "", "", "", "", "", fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
			}
			pw = secretData.Password
			desc = secretData.Description
		}
	case "password-description-totp":
		name = resource.Name
		username = resource.Username
		uri = resource.URI
		// Only parse secret data if it was decrypted
		if rawSecretData != "" {
			var secretData api.SecretDataTypePasswordDescriptionTOTP
			err = json.Unmarshal([]byte(rawSecretData), &secretData)
			if err != nil {
				return "", "", "", "", "", "", fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
			}
			pw = secretData.Password
			desc = secretData.Description
		}
	case "totp":
		name = resource.Name
		username = resource.Username
		uri = resource.URI
		// nothing fits into the interface in this case
	case "v5-default":
		rawMetadata, err := GetResourceMetadata(ctx, c, &resource, &rType)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Getting Metadata: %w", err)
		}

		var metadata api.ResourceMetadataTypeV5Default
		err = json.Unmarshal([]byte(rawMetadata), &metadata)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Parsing Decrypted Metadata: %w", err)
		}

		name = metadata.Name
		username = metadata.Username
		if len(metadata.URIs) != 0 {
			uri = metadata.URIs[0]
		}

		// Only parse secret data if it was decrypted
		if rawSecretData != "" {
			var secretData api.SecretDataTypeV5Default
			err = json.Unmarshal([]byte(rawSecretData), &secretData)
			if err != nil {
				return "", "", "", "", "", "", fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
			}
			pw = secretData.Password
			desc = secretData.Description
		}
	case "v5-default-with-totp":
		rawMetadata, err := GetResourceMetadata(ctx, c, &resource, &rType)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Getting Metadata: %w", err)
		}

		var metadata api.ResourceMetadataTypeV5DefaultWithTOTP
		err = json.Unmarshal([]byte(rawMetadata), &metadata)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Parsing Decrypted Metadata: %w", err)
		}

		name = metadata.Name
		username = metadata.Username
		if len(metadata.URIs) != 0 {
			uri = metadata.URIs[0]
		}

		// Only parse secret data if it was decrypted
		if rawSecretData != "" {
			var secretData api.SecretDataTypeV5DefaultWithTOTP
			err = json.Unmarshal([]byte(rawSecretData), &secretData)
			if err != nil {
				return "", "", "", "", "", "", fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
			}
			pw = secretData.Password
			desc = secretData.Description
		}
	case "v5-password-string":
		rawMetadata, err := GetResourceMetadata(ctx, c, &resource, &rType)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Getting Metadata: %w", err)
		}

		var metadata api.ResourceMetadataTypeV5PasswordString
		err = json.Unmarshal([]byte(rawMetadata), &metadata)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Parsing Decrypted Metadata: %w", err)
		}

		name = metadata.Name
		username = metadata.Username
		if len(metadata.URIs) != 0 {
			uri = metadata.URIs[0]
		}

		// Not available in the Secret
		desc = metadata.Description

		pw = rawSecretData
	case "v5-totp-standalone":
		rawMetadata, err := GetResourceMetadata(ctx, c, &resource, &rType)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Getting Metadata: %w", err)
		}

		var metadata api.ResourceMetadataTypeV5TOTPStandalone
		err = json.Unmarshal([]byte(rawMetadata), &metadata)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Parsing Decrypted Metadata: %w", err)
		}

		name = metadata.Name
		if len(metadata.URIs) != 0 {
			uri = metadata.URIs[0]
		}
	default:
		return "", "", "", "", "", "", fmt.Errorf("Unknown ResourceType: %v", rType.Slug)
	}
	return resource.FolderParentID, name, username, uri, pw, desc, nil
}
