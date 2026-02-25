package helper

import (
	"encoding/json"
	"fmt"

	"github.com/passbolt/go-passbolt/api"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func validateSecretData(rType *api.ResourceType, secretData string) error {
	// TODO Remove password-string when v4 Resources are unsupported
	// with the Resource Type password-string the Secret is not json and can't be properly validated, so skip the check here
	if rType.Slug == "password-string" || rType.Slug == "v5-password-string" {
		if len(secretData) > 4096 {
			return fmt.Errorf("password is longer than 4096")
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
		// Workaround for inconsistant API Responses where sometime the Schema is embedded directly and sometimes it's escaped as a string
		if err.Error() == "json: cannot unmarshal string into Go value of type api.ResourceTypeSchema" {
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

	err = comp.AddResource("secret.json", schemaDefinition.Secret)
	if err != nil {
		return fmt.Errorf("adding Json Schema: %w", err)
	}

	schema, err := comp.Compile("secret.json")
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
