package helper

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/passbolt/go-passbolt/api"
)

func GetResourceMetadata(ctx context.Context, c *api.Client, resource api.Resource, rType api.ResourceType) (string, error) {
	keys, err := c.GetMetadataKeys(ctx, &api.GetMetadataKeysOptions{
		ContainMetadataPrivateKeys: true,
	})
	if err != nil {
		return "", fmt.Errorf("Get Metadata Key: %w", err)
	}

	// TODO Get Key by id?
	if len(keys) != 1 {
		return "", fmt.Errorf("Not Exactly One Metadatakey Available")
	}

	if len(keys[0].MetadataPrivateKeys) == 0 {
		return "", fmt.Errorf("No Metadata Private key for our user")
	}

	if len(keys[0].MetadataPrivateKeys) > 1 {
		return "", fmt.Errorf("More than 1 metadata Private key for our user")
	}

	var privMetdata api.MetadataPrivateKey = keys[0].MetadataPrivateKeys[0]
	if *privMetdata.UserID != c.GetUserID() {
		return "", fmt.Errorf("MetadataPrivateKey is not for our user id: %v", privMetdata.UserID)
	}

	decPrivMetadatakey, err := c.DecryptMessage(privMetdata.Data)
	if err != nil {
		return "", fmt.Errorf("Decrypt Metadata Private Key Data: %w", err)
	}

	var data api.MetadataPrivateKeyData
	err = json.Unmarshal([]byte(decPrivMetadatakey), &data)
	if err != nil {
		return "", fmt.Errorf("Parse Metadata Private Key Data")
	}

	metadataPrivateKeyObj, err := api.GetPrivateKeyFromArmor(data.ArmoredKey, []byte(data.Passphrase))
	if err != nil {
		return "", fmt.Errorf("Get Metadata Private Key: %w", err)
	}

	decMetadata, err := c.DecryptMetadata(metadataPrivateKeyObj, resource.Metadata)
	if err != nil {
		return "", fmt.Errorf("Decrypt Metadata: %w", err)
	}
	/*


		var schemaDefinition api.ResourceTypeSchema
		err = json.Unmarshal([]byte(rType.Definition), &schemaDefinition)
		if err != nil {
			// Workaround for inconsistant API Responses where sometime the Schema is embedded directly and sometimes it's escaped as a string
			if err.Error() == "json: cannot unmarshal string into Go value of type api.ResourceTypeSchema" {
				var tmp string
				err = json.Unmarshal([]byte(rType.Definition), &tmp)
				if err != nil {
					return "", fmt.Errorf("Workaround Unmarshal Json Schema String: %w", err)
				}

				err = json.Unmarshal([]byte(tmp), &schemaDefinition)
				if err != nil {
					return "", fmt.Errorf("Workaround Unmarshal Json Schema: %w", err)
				}

			} else {
				return "", fmt.Errorf("Unmarshal Json Schema: %w", err)
			}
		}

		comp := jsonschema.NewCompiler()

		err = comp.AddResource("metadata.json", bytes.NewReader(schemaDefinition.Secret))
		if err != nil {
			return "", fmt.Errorf("Adding Json Schema: %w", err)
		}

		schema, err := comp.Compile("metadata.json")
		if err != nil {
			return "", fmt.Errorf("Compiling Json Schema: %w", err)
		}

		err = schema.Validate(strings.NewReader(decMetadata))
		if err != nil {
			return "", fmt.Errorf("Validating Secret Data: %w", err)
		}
	*/

	return decMetadata, nil
}
