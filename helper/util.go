package helper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/passbolt/go-passbolt/api"
	"github.com/santhosh-tekuri/jsonschema"
)

func getPublicKeyByUserID(userID string, Users []api.User) (string, error) {
	for _, user := range Users {
		if user.ID == userID {
			return user.GPGKey.ArmoredKey, nil
		}
	}
	return "", fmt.Errorf("Cannot Find Key for user id %v", userID)
}

func getMembershipByUserID(memberships []api.GroupMembership, userID string) (*api.GroupMembership, error) {
	for _, membership := range memberships {
		if membership.UserID == userID {
			return &membership, nil
		}
	}
	return nil, fmt.Errorf("Cannot Find Membership for user id %v", userID)
}

func getSecretByResourceID(secrets []api.Secret, resourceID string) (*api.Secret, error) {
	for _, secret := range secrets {
		if secret.ResourceID == resourceID {
			return &secret, nil
		}
	}
	return nil, fmt.Errorf("Cannot Find Secret for id %v", resourceID)
}

func validateSecretData(rType *api.ResourceType, secretData string) error {
	var schemaDefinition api.ResourceTypeSchema
	err := json.Unmarshal([]byte(rType.Definition), &schemaDefinition)
	if err != nil {
		// Workaround for inconsistant API Responses where sometime the Schema is embedded directly and sometimes it's escaped as a string
		if err.Error() == "json: cannot unmarshal string into Go value of type api.ResourceTypeSchema" {
			var tmp string
			err = json.Unmarshal([]byte(rType.Definition), &tmp)
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
		return fmt.Errorf("Validating Secret Data: %w", err)
	}
	return nil
}
