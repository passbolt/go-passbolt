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

// Regression test for the cache key: ID-keyed entries collided for types with an empty ID.
func TestCompileSection_DistinctSlugsWithEmptyIDsDoNotCollide(t *testing.T) {
	// v5-pin-code requires "pin_code" in its secret; v5-default requires "password".
	// Neither document validates against the other's schema.
	pinCode := &api.ResourceType{Slug: "v5-pin-code"}
	pinSecret := `{"object_type":"PASSBOLT_SECRET_DATA","pin_code":"1234"}`
	def := &api.ResourceType{Slug: "v5-default"}
	defSecret := `{"object_type":"PASSBOLT_SECRET_DATA","password":"p"}`

	if pinCode.ID != "" || def.ID != "" {
		t.Fatal("this test is meaningless unless both resource types have an empty ID")
	}

	if err := validateSecretData(pinCode, pinSecret); err != nil {
		t.Errorf("v5-pin-code secret rejected: %v", err)
	}
	if err := validateSecretData(def, defSecret); err != nil {
		t.Errorf("v5-default secret rejected (cache collision on the empty ID?): %v", err)
	}
	// And the reverse pairing must fail, proving the two really are distinct schemas.
	if err := validateSecretData(pinCode, defSecret); err == nil {
		t.Error("v5-pin-code accepted a v5-default secret")
	}
}
