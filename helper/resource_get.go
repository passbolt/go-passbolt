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

// GetResourceFromData Decrypts Resources using only local data, the Resource object must inlude the secret
// With v5 This needs network calls for Metadata of v5 Resources
func GetResourceFromData(c *api.Client, resource api.Resource, secret api.Secret, rType api.ResourceType) (string, string, string, string, string, string, error) {
	var name string
	var username string
	var uri string
	var pw string
	var desc string

	ctx := context.TODO()

	switch rType.Slug {
	case "password-string":
		var err error
		pw, err = c.DecryptMessage(secret.Data)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Decrypting Secret Data: %w", err)
		}
		name = resource.Name
		username = resource.Username
		uri = resource.URI
		desc = resource.Description
	case "password-and-description":
		rawSecretData, err := c.DecryptMessage(secret.Data)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Decrypting Secret Data: %w", err)
		}

		var secretData api.SecretDataTypePasswordAndDescription
		err = json.Unmarshal([]byte(rawSecretData), &secretData)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
		}
		name = resource.Name
		username = resource.Username
		uri = resource.URI
		pw = secretData.Password
		desc = secretData.Description
	case "password-description-totp":
		rawSecretData, err := c.DecryptMessage(secret.Data)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Decrypting Secret Data: %w", err)
		}

		var secretData api.SecretDataTypePasswordDescriptionTOTP
		err = json.Unmarshal([]byte(rawSecretData), &secretData)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
		}
		name = resource.Name
		username = resource.Username
		uri = resource.URI
		pw = secretData.Password
		desc = secretData.Description
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

		rawSecretData, err := c.DecryptMessage(secret.Data)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Decrypting Secret Data: %w", err)
		}

		var secretData api.SecretDataTypeV5Default
		err = json.Unmarshal([]byte(rawSecretData), &secretData)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
		}
		pw = secretData.Password
		desc = secretData.Description
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

		rawSecretData, err := c.DecryptMessage(secret.Data)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Decrypting Secret Data: %w", err)
		}

		var secretData api.SecretDataTypeV5DefaultWithTOTP
		err = json.Unmarshal([]byte(rawSecretData), &secretData)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Parsing Decrypted Secret Data: %w", err)
		}
		pw = secretData.Password
		desc = secretData.Description
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

		rawSecretData, err := c.DecryptMessage(secret.Data)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Decrypting Secret Data: %w", err)
		}

		pw = rawSecretData
	case "v5-totp-standalone":
		// nothing fits into the interface in this case
	default:
		return "", "", "", "", "", "", fmt.Errorf("Unknown ResourceType: %v", rType.Slug)
	}
	return resource.FolderParentID, name, username, uri, pw, desc, nil
}
