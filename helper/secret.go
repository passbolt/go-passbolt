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

	schemaDefinition, err := rType.Schema()
	if err != nil {
		if errors.Is(err, api.ErrSchemaUnavailable) {
			return fmt.Errorf("%w: %v", ErrUnsupportedResourceType, rType.Slug)
		}
		return fmt.Errorf("resolving schema: %w", err)
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
