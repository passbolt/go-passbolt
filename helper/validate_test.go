package helper

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/passbolt/go-passbolt/api"
)

// An unbundled slug yields ErrUnsupportedResourceType from both helpers; a server-provided
// definition does not rescue it.
func TestValidate_UnbundledSlugUnsupported(t *testing.T) {
	definition := json.RawMessage(`{"resource":{"type":"object","properties":{"name":{}}},"secret":{"type":"object"}}`)

	for _, rt := range []*api.ResourceType{
		{Slug: "not-a-bundled-slug"},
		{Slug: "not-a-bundled-slug", Definition: definition},
	} {
		if err := validateMetadata(rt, `{"name":"x"}`); !errors.Is(err, ErrUnsupportedResourceType) {
			t.Errorf("validateMetadata: expected ErrUnsupportedResourceType, got %v", err)
		}
		if err := validateSecretData(rt, `{"password":"p"}`); !errors.Is(err, ErrUnsupportedResourceType) {
			t.Errorf("validateSecretData: expected ErrUnsupportedResourceType, got %v", err)
		}
	}
}
