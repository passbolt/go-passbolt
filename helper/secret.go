package helper

import (
	"encoding/json"
	"fmt"

	"github.com/passbolt/go-passbolt/api"
)

// validateSecretData validates a decrypted secret against the bundled schema for its resource
// type. See validationMode for the read/write distinction.
func validateSecretData(rType *api.ResourceType, secretData string, mode validationMode) error {
	// A plain-string secret is a raw password, not JSON, so only length can be checked. Both
	// modes reduce to the same check here.
	if rType.IsSecretString() {
		if len(secretData) > 4096 {
			return ErrPasswordTooLong
		}
		return nil
	}

	schema, err := compileSection(rType, schemaSectionSecret, mode)
	if err != nil {
		return err
	}

	var parsedSecretData map[string]any
	if err := json.Unmarshal([]byte(secretData), &parsedSecretData); err != nil {
		return fmt.Errorf("unmarshal Secret: %w", err)
	}

	if err := schema.Validate(parsedSecretData); err != nil {
		return wrapValidationError("Secret Data", err)
	}
	return nil
}
