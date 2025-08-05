package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/passbolt/go-passbolt/api"
	"github.com/santhosh-tekuri/jsonschema"
)

func GetResourceMetadata(ctx context.Context, c *api.Client, resource *api.Resource, rType *api.ResourceType) (string, error) {
	var metadatakey *crypto.Key
	if resource.MetadataKeyType == api.MetadataKeyTypeUserKey {
		tmp, err := c.GetUserPrivateKeyCopy()
		if err != nil {
			return "", fmt.Errorf("Get Private Key Copy: %w", err)
		}
		metadatakey = tmp
	} else {
		key, err := c.GetMetadataKeyById(ctx, resource.MetadataKeyID)
		if err != nil {
			return "", fmt.Errorf("Get Metadata Key by ID: %w", err)
		}
		metadatakey = key
	}

	decMetadata, err := c.DecryptMetadata(metadatakey, resource.Metadata)
	if err != nil {
		return "", fmt.Errorf("Decrypt Metadata: %w", err)
	}

	err = validateMetadata(rType, string(decMetadata))
	if err != nil {
		return "", fmt.Errorf("Validate Metadata: %w", err)
	}

	return decMetadata, nil
}

func validateMetadata(rType *api.ResourceType, metadata string) error {
	var schemaDefinition api.ResourceTypeSchema
	definition := rType.Definition

	// Fallback schema
	if string(definition) == "[]" || string(definition) == "\"[]\"" {
		tmp, ok := api.ResourceSchemas[rType.Slug]
		if !ok {
			return fmt.Errorf("Server Does not have the Required json Schema and there is no fallback available for type: %v", rType.Slug)
		}
		definition = tmp
	}

	err := json.Unmarshal([]byte(definition), &schemaDefinition)
	if err != nil {
		// Workaround for inconsistant API Responses where sometime the Schema is embedded directly and sometimes it's escaped as a string
		if err.Error() == "json: cannot unmarshal string into Go value of type api.ResourceTypeSchema" {
			var tmp string
			err = json.Unmarshal([]byte(definition), &tmp)
			if err != nil {
				return fmt.Errorf("Workaround Unmarshal Json Schema String: %w", err)
			}

			err = json.Unmarshal([]byte(tmp), &schemaDefinition)
			if err != nil {
				return fmt.Errorf("Workaround Unmarshal Json Schema: %w", err)
			}
		} else {
			return fmt.Errorf("Unmarshal Json Schema: %w", err)
		}
	}

	comp := jsonschema.NewCompiler()

	err = comp.AddResource("metadata.json", bytes.NewReader(schemaDefinition.Resource))
	if err != nil {
		return fmt.Errorf("Adding Json Schema: %w", err)
	}

	schema, err := comp.Compile("metadata.json")
	if err != nil {
		return fmt.Errorf("Compiling Json Schema: %w", err)
	}

	err = schema.Validate(strings.NewReader(metadata))
	if err != nil {
		return fmt.Errorf("Validating Metadata with Schema: %w", err)
	}
	return nil
}
