package helper

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/passbolt/go-passbolt/api"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func validateSecretData(rType *api.ResourceType, secretData string) error {
	// When the secret is a plain string (not JSON), we can only validate length
	if rType.IsSecretString() {
		if len(secretData) > 4096 {
			return ErrPasswordTooLong
		}
		return nil
	}

	var schemaDefinition api.ResourceTypeSchema
	definition := rType.Definition

	// Fallback schema
	if string(definition) == "[]" || string(definition) == "\"[]\"" {
		tmp, ok := api.ResourceSchemas[rType.Slug]
		if !ok {
			return fmt.Errorf("%w: %v (no schema available)", ErrUnsupportedResourceType, rType.Slug)
		}
		definition = tmp
	}

	err := json.Unmarshal([]byte(definition), &schemaDefinition)
	if err != nil {
		// Workaround for inconsistent API Responses where sometimes the Schema is embedded directly and sometimes it's escaped as a string
		var unmarshalErr *json.UnmarshalTypeError
		if errors.As(err, &unmarshalErr) {
			var tmp string
			err = json.Unmarshal([]byte(definition), &tmp)
			if err != nil {
				return fmt.Errorf("workaround Unmarshal Json Schema String: %w", err)
			}

			err = json.Unmarshal([]byte(tmp), &schemaDefinition)
			if err != nil {
				return fmt.Errorf("workaround Unmarshal Json Schema: %w", err)
			}
		} else {
			return fmt.Errorf("unmarshal Json Schema: %w", err)
		}
	}

	comp := jsonschema.NewCompiler()

	err = comp.AddResource("urn:passbolt:schema:secret", schemaDefinition.Secret)
	if err != nil {
		return fmt.Errorf("adding Json Schema: %w", err)
	}

	schema, err := comp.Compile("urn:passbolt:schema:secret")
	if err != nil {
		return fmt.Errorf("compiling Json Schema: %w", err)
	}

	var parsedSecretData map[string]any
	err = json.Unmarshal([]byte(secretData), &parsedSecretData)
	if err != nil {
		return fmt.Errorf("unmarshal Secret: %w", err)
	}

	err = schema.Validate(parsedSecretData)
	if err != nil {
		return fmt.Errorf("validating Secret Data with Schema: %w", err)
	}
	return nil
}
