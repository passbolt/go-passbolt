package helper

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
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
	if c.MetadataTypeSettings().AllowCreationOfV5Resources == false {
		return "", fmt.Errorf("Creation of V5 Passwords is disabled on this Server")
	}

	types, err := c.GetResourceTypes(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("Getting ResourceTypes: %w", err)
	}
	var rType *api.ResourceType
	for _, tmp := range types {
		if tmp.Slug == "v5-default" {
			rType = &tmp
			break
		}
	}
	if rType == nil {
		return "", fmt.Errorf("Cannot find Resource type password-and-description")
	}

	// Base Resource
	resource := api.Resource{
		ResourceTypeID: rType.ID,
		FolderParentID: folderParentID,
	}

	// Resource Metadata
	meta := api.ResourceMetadataTypeV5Default{
		ObjectType:     api.PASSBOLT_OBJECT_TYPE_RESOURCE_METADATA,
		ResourceTypeID: rType.ID,
		Name:           name,
		Username:       username,
		URIs:           []string{uri},
	}

	metaData, err := json.Marshal(&meta)
	if err != nil {
		return "", fmt.Errorf("Marshalling metadata: %w", err)
	}

	err = validateMetadata(rType, string(metaData))
	if err != nil {
		return "", fmt.Errorf("Validating metadata: %w", err)
	}

	var publicMetadataKey *crypto.Key
	// Since we are not sharing, use the Personal Key if allowed
	if c.MetadataKeySettings().AllowUsageOfPersonalKeys {
		publicMetadataKey, err = c.GetUserPrivateKeyCopy()
		if err != nil {
			return "", fmt.Errorf("Get User Private Key: %w", err)
		}

		me, err := c.GetMe(ctx)
		if err != nil {
			return "", fmt.Errorf("Get User Me: %w", err)
		}

		if me.GPGKey == nil {
			return "", fmt.Errorf("User Me GPG Key nil")
		}

		resource.MetadataKeyID = me.GPGKey.ID
		resource.MetadataKeyType = api.MetadataKeyTypeUserKey
	} else {
		keys, err := c.GetMetadataKeys(ctx, nil)
		if err != nil {
			return "", fmt.Errorf("Get Metadata Key: %w", err)
		}

		// TODO Get Key by id?
		if len(keys) != 1 {
			return "", fmt.Errorf("Not Exactly One Metadatakey Available")
		}

		publicMetadataKey, err = crypto.NewKeyFromArmored(keys[0].ArmoredKey)
		if err != nil {
			return "", fmt.Errorf("Get Metadata Public Key: %w", err)
		}

		resource.MetadataKeyID = keys[0].ID
		resource.MetadataKeyType = api.MetadataKeyTypeSharedKey
	}

	encMetadata, err := c.EncryptMessageWithKey(publicMetadataKey, string(metaData))
	if err != nil {
		return "", fmt.Errorf("Encrypt Metadata: %w", err)
	}
	resource.Metadata = encMetadata

	// Resource Secret
	secret := api.SecretDataTypeV5Default{
		ObjectType:  api.PASSBOLT_OBJECT_TYPE_SECRET_DATA,
		Password:    password,
		Description: description,
	}

	secretData, err := json.Marshal(&secret)
	if err != nil {
		return "", fmt.Errorf("Marshalling Secret Data: %w", err)
	}

	err = validateSecretData(rType, string(secretData))
	if err != nil {
		return "", fmt.Errorf("Validating Secret Data: %w", err)
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

func CreateResourceV4(ctx context.Context, c *api.Client, folderParentID, name, username, uri, password, description string) (string, error) {
	if c.MetadataTypeSettings().AllowCreationOfV4Resources == false {
		return "", fmt.Errorf("Creation of V4 Passwords is disabled on this Server")
	}

	types, err := c.GetResourceTypes(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("Getting ResourceTypes: %w", err)
	}
	var rType *api.ResourceType
	for _, tmp := range types {
		if tmp.Slug == "password-and-description" {
			rType = &tmp
			break
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

	err = validateSecretData(rType, string(secretData))
	if err != nil {
		return "", fmt.Errorf("Validating Secret Data: %w", err)
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
	if c.MetadataTypeSettings().AllowCreationOfV4Resources == false {
		return "", fmt.Errorf("Creation of V4 Passwords is disabled on this Server")
	}

	// TODO Create a v5-password-string if v5 is enabled

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
		rawMetadata, err := GetResourceMetadata(ctx, c, resource, rType)
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
		rawMetadata, err := GetResourceMetadata(ctx, c, resource, rType)
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
		rawMetadata, err := GetResourceMetadata(ctx, c, resource, rType)
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
		Name:           resource.Name,
		Username:       resource.Username,
		URI:            resource.URI,
	}

	if name != "" {
		newResource.Name = name
	}
	if username != "" {
		newResource.Username = username
	}
	if uri != "" {
		newResource.URI = uri
	}

	var secretData string
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
