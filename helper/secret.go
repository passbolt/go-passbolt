package helper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/passbolt/go-passbolt/api"
	"github.com/santhosh-tekuri/jsonschema"
)

func validateSecretData(rType *api.ResourceType, secretData string) error {
	// TODO Remove when v4 Resources are unsupported
	// with the Resource Type password-string the Secret is not json and can't be properly validated, so skip the check here
	if rType.Slug == "password-string" {
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

	err = comp.AddResource("secret.json", bytes.NewReader(schemaDefinition.Secret))
	if err != nil {
		return fmt.Errorf("Adding Json Schema: %w", err)
	}

	schema, err := comp.Compile("secret.json")
	if err != nil {
		return fmt.Errorf("Compiling Json Schema: %w", err)
	}

	err = schema.Validate(strings.NewReader(secretData))
	if err != nil {
		return fmt.Errorf("Validating Secret Data with Schema: %w", err)
	}
	return nil
}
