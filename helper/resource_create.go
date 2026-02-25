package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/passbolt/go-passbolt/api"
)

// CreateResource Creates a Resource, Creates a v4 or v5 Resources based on the server Preference
func CreateResource(ctx context.Context, c *api.Client, folderParentID, name, username, uri, password, description string) (string, error) {
	// Create a v5 Password if that is the Server Default
	if c.MetadataTypeSettings().DefaultResourceType == api.PassboltAPIVersionTypeV5 {
		return CreateResourceV5(ctx, c, folderParentID, name, username, uri, password, description)
	} else {
		return CreateResourceV4(ctx, c, folderParentID, name, username, uri, password, description)
	}
}

func CreateResourceV5(ctx context.Context, c *api.Client, folderParentID, name, username, uri, password, description string) (string, error) {
	if !c.MetadataTypeSettings().AllowCreationOfV5Resources {
		return "", fmt.Errorf("creation of V5 Passwords is disabled on this Server")
	}

	types, err := c.GetResourceTypes(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("getting ResourceTypes: %w", err)
	}
	var rType *api.ResourceType
	for _, tmp := range types {
		if tmp.Slug == "v5-default" {
			rType = &tmp
			break
		}
	}
	if rType == nil {
		return "", fmt.Errorf("cannot find Resource type password-and-description")
	}

	// Base Resource
	resource := api.Resource{
		ResourceTypeID: rType.ID,
		FolderParentID: folderParentID,
	}

	// Resource Metadata
	meta := api.ResourceMetadataTypeV5Default{
		ObjectType:     api.PassboltObjectTypeResourceMetadata,
		ResourceTypeID: rType.ID,
		Name:           name,
		Username:       username,
		URIs:           []string{uri},
	}

	metaData, err := json.Marshal(&meta)
	if err != nil {
		return "", fmt.Errorf("marshalling metadata: %w", err)
	}

	err = validateMetadata(rType, string(metaData))
	if err != nil {
		return "", fmt.Errorf("validating metadata: %w", err)
	}

	metadataKeyID, metadataKeyType, publicMetadataKey, err := c.GetMetadataKey(ctx, true)
	if err != nil {
		return "", fmt.Errorf("get Metadata Key: %w", err)
	}
	resource.MetadataKeyID = metadataKeyID
	resource.MetadataKeyType = metadataKeyType

	encMetadata, err := c.EncryptMessageWithKey(publicMetadataKey, string(metaData))
	if err != nil {
		return "", fmt.Errorf("encrypt Metadata: %w", err)
	}
	resource.Metadata = encMetadata

	// Resource Secret
	secret := api.SecretDataTypeV5Default{
		ObjectType:  api.PassboltObjectTypeSecretData,
		Password:    password,
		Description: description,
	}

	secretData, err := json.Marshal(&secret)
	if err != nil {
		return "", fmt.Errorf("marshalling Secret Data: %w", err)
	}

	err = validateSecretData(rType, string(secretData))
	if err != nil {
		return "", fmt.Errorf("validating Secret Data: %w", err)
	}

	encSecretData, err := c.EncryptMessage(string(secretData))
	if err != nil {
		return "", fmt.Errorf("encrypting Secret Data for User me: %w", err)
	}
	resource.Secrets = []api.Secret{{Data: encSecretData}}

	passwordExpirySettings := c.GetPasswordExpirySettings()
	if passwordExpirySettings.DefaultExpiryPeriod != 0 {
		expiry := time.Now().Add(time.Hour * 24 * time.Duration(passwordExpirySettings.DefaultExpiryPeriod))
		resource.Expired = &api.Time{Time: expiry}
	}

	newresource, err := c.CreateResource(ctx, resource)
	if err != nil {
		return "", fmt.Errorf("creating Resource: %w", err)
	}
	return newresource.ID, nil
}

func CreateResourceV4(ctx context.Context, c *api.Client, folderParentID, name, username, uri, password, description string) (string, error) {
	if !c.MetadataTypeSettings().AllowCreationOfV4Resources {
		return "", fmt.Errorf("creation of V4 Passwords is disabled on this Server")
	}

	types, err := c.GetResourceTypes(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("getting ResourceTypes: %w", err)
	}
	var rType *api.ResourceType
	for _, tmp := range types {
		if tmp.Slug == "password-and-description" {
			rType = &tmp
			break
		}
	}
	if rType == nil {
		return "", fmt.Errorf("cannot find Resource type password-and-description")
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
		return "", fmt.Errorf("marshalling Secret Data: %w", err)
	}

	err = validateSecretData(rType, string(secretData))
	if err != nil {
		return "", fmt.Errorf("validating Secret Data: %w", err)
	}

	encSecretData, err := c.EncryptMessage(string(secretData))
	if err != nil {
		return "", fmt.Errorf("encrypting Secret Data for User me: %w", err)
	}
	resource.Secrets = []api.Secret{{Data: encSecretData}}

	passwordExpirySettings := c.GetPasswordExpirySettings()
	if passwordExpirySettings.DefaultExpiryPeriod != 0 {
		expiry := time.Now().Add(time.Hour * 24 * time.Duration(passwordExpirySettings.DefaultExpiryPeriod))
		resource.Expired = &api.Time{Time: expiry}
	}

	newresource, err := c.CreateResource(ctx, resource)
	if err != nil {
		return "", fmt.Errorf("creating Resource: %w", err)
	}
	return newresource.ID, nil
}

// CreateResourceSimple Creates a Legacy Resource where only the Password is Encrypted and Returns the Resources ID
func CreateResourceSimple(ctx context.Context, c *api.Client, folderParentID, name, username, uri, password, description string) (string, error) {
	if !c.MetadataTypeSettings().AllowCreationOfV4Resources {
		return "", fmt.Errorf("creation of V4 Passwords is disabled on this Server")
	}

	// TODO Create a v5-password-string if v5 is enabled

	enc, err := c.EncryptMessage(password)
	if err != nil {
		return "", fmt.Errorf("encrypting Password: %w", err)
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
		return "", fmt.Errorf("creating Resource: %w", err)
	}
	return resource.ID, nil
}
