package helper

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/speatzle/go-passbolt/api"
)

// CreateResource Creates a Resource where the Password and Description are Encrypted and Returns the Resources ID
func CreateResource(ctx context.Context, c *api.Client, folderParentID, name, username, uri, password, description string) (string, error) {
	types, err := c.GetResourceTypes(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("Getting ResourceTypes: %w", err)
	}
	var rType *api.ResourceType
	for _, tmp := range types {
		if tmp.Slug == "password-and-description" {
			rType = &tmp
		}
	}
	if rType == nil {
		return "", fmt.Errorf("Cannot find Resource type password-and-description")
	}

	resource := api.Resource{
		ResourceTypeID: rType.ID,
		FolderParentID: folderParentID,
		Name:           name,
		Username:       username,
		URI:            uri,
	}

	tmp := api.SecretDataTypePasswordAndDescription{
		Password:    password,
		Description: description,
	}
	secretData, err := json.Marshal(&tmp)
	if err != nil {
		return "", fmt.Errorf("Marshalling Secret Data: %w", err)
	}

	encSecretData, err := c.EncryptMessage(string(secretData))
	if err != nil {
		return "", fmt.Errorf("Encrypting Secret Data for User me: %w", err)
	}
	resource.Secrets = []api.Secret{{Data: encSecretData}}

	newresource, err := c.CreateResource(ctx, resource)
	if err != nil {
		return "", fmt.Errorf("Creating Resource: %w", err)
	}
	return newresource.ID, nil
}

// CreateResourceSimple Creates a Legacy Resource where only the Password is Encrypted and Returns the Resources ID
func CreateResourceSimple(ctx context.Context, c *api.Client, folderParentID, name, username, uri, password, description string) (string, error) {
	enc, err := c.EncryptMessage(password)
	if err != nil {
		return "", fmt.Errorf("Encrypting Password: %w", err)
	}

	res := api.Resource{
		Name:           name,
		URI:            uri,
		Username:       username,
		FolderParentID: folderParentID,
		Description:    description,
		Secrets: []api.Secret{
			{Data: enc},
		},
	}

	resource, err := c.CreateResource(ctx, res)
	if err != nil {
		return "", fmt.Errorf("Creating Resource: %w", err)
	}
	return resource.ID, nil
}

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
	var pw string
	var desc string
	switch rType.Slug {
	case "password-string":
		pw, err = c.DecryptMessage(secret.Data)
		if err != nil {
			return "", "", "", "", "", "", fmt.Errorf("Decrypting Secret Data: %w", err)
		}
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
		pw = secretData.Password
		desc = secretData.Description
	default:
		return "", "", "", "", "", "", fmt.Errorf("Unknown ResourceType: %v", rType.Slug)
	}
	return resource.FolderParentID, resource.Name, resource.Username, resource.URI, pw, desc, nil
}

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
		Name:           name,
		Username:       username,
		URI:            uri,
	}

	var secretData string
	switch rType.Slug {
	case "password-string":
		newResource.Description = description
		secretData = password
	case "password-and-description":
		tmp := api.SecretDataTypePasswordAndDescription{
			Password:    password,
			Description: description,
		}
		res, err := json.Marshal(&tmp)
		if err != nil {
			return fmt.Errorf("Marshalling Secret Data: %w", err)
		}
		secretData = string(res)
	default:
		return fmt.Errorf("Unknown ResourceType: %v", rType.Slug)
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
			encSecretData, err = c.EncryptMessageWithPublicKey(user.GPGKey.ArmoredKey, secretData)
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

// DeleteResource Deletes a Resource
func DeleteResource(ctx context.Context, c *api.Client, resourceID string) error {
	err := c.DeleteResource(ctx, resourceID)
	if err != nil {
		return fmt.Errorf("Deleting Resource: %w", err)
	}
	return nil
}

// MoveResource Moves a Resource into a Folder
func MoveResource(ctx context.Context, c *api.Client, resourceID, folderParentID string) error {
	err := c.MoveResource(ctx, resourceID, folderParentID)
	if err != nil {
		return fmt.Errorf("Moveing Resource: %w", err)
	}
	return err
}
