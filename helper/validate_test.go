package helper

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/passbolt/go-passbolt/api"
)

// These tests exercise the strict-write / lenient-read validation against the embedded
// v5-default schema (no server needed). They are the regression guard for the directional
// strictness introduced when the embedded schemas became the source of truth.

// TestValidateMetadata_StrictRejectsUnknownField: on the write path the SDK must reject a field
// the resource type does not define, catching caller/SDK bugs before they are encrypted.
func TestValidateMetadata_StrictRejectsUnknownField(t *testing.T) {
	rt := &api.ResourceType{Slug: "v5-default"}
	meta := `{"name":"x","object_type":"PASSBOLT_RESOURCE_METADATA","resource_type_id":"r","bogus":"nope"}`
	if err := validateMetadata(rt, meta, validateWrite); err == nil {
		t.Fatal("expected strict write to reject unknown field 'bogus'")
	}
}

// TestValidateMetadata_LenientAcceptsUnknownField: the read path must tolerate fields a newer
// server added that this SDK's schema doesn't model (forward compatibility).
func TestValidateMetadata_LenientAcceptsUnknownField(t *testing.T) {
	rt := &api.ResourceType{Slug: "v5-default"}
	meta := `{"name":"x","object_type":"PASSBOLT_RESOURCE_METADATA","resource_type_id":"r","futureField":"ok"}`
	if err := validateMetadata(rt, meta, validateRead); err != nil {
		t.Fatalf("expected lenient read to accept unknown field, got %v", err)
	}
}

// Strict write must accept the envelope fields the SDK adds to every v5 metadata document.
func TestValidateMetadata_StrictAcceptsEnvelope(t *testing.T) {
	rt := &api.ResourceType{Slug: "v5-default"}
	meta := `{"name":"x","username":"u","uris":["https://x.test"],"object_type":"PASSBOLT_RESOURCE_METADATA","resource_type_id":"r"}`
	if err := validateMetadata(rt, meta, validateWrite); err != nil {
		t.Fatalf("strict write rejected the SDK's own envelope metadata: %v", err)
	}
}

func TestValidateSecretData_StrictRejectsUnknownField(t *testing.T) {
	rt := &api.ResourceType{Slug: "v5-default"}
	secret := `{"object_type":"PASSBOLT_SECRET_DATA","password":"p","bogus":"x"}`
	if err := validateSecretData(rt, secret, validateWrite); err == nil {
		t.Fatal("expected strict write to reject unknown secret field 'bogus'")
	}
}

func TestValidateSecretData_LenientAcceptsUnknownField(t *testing.T) {
	rt := &api.ResourceType{Slug: "v5-default"}
	secret := `{"object_type":"PASSBOLT_SECRET_DATA","password":"p","futureField":"x"}`
	if err := validateSecretData(rt, secret, validateRead); err != nil {
		t.Fatalf("expected lenient read to accept unknown secret field, got %v", err)
	}
}

// An unbundled slug yields ErrUnsupportedResourceType from both helpers; a server-provided
// definition does not rescue it.
func TestValidate_UnbundledSlugUnsupported(t *testing.T) {
	definition := json.RawMessage(`{"resource":{"type":"object","properties":{"name":{}}},"secret":{"type":"object"}}`)

	for _, rt := range []*api.ResourceType{
		{Slug: "not-a-bundled-slug"},
		{Slug: "not-a-bundled-slug", Definition: definition},
	} {
		for _, mode := range []validationMode{validateRead, validateWrite} {
			if err := validateMetadata(rt, `{"name":"x"}`, mode); !errors.Is(err, ErrUnsupportedResourceType) {
				t.Errorf("validateMetadata(mode=%d): expected ErrUnsupportedResourceType, got %v", mode, err)
			}
			if err := validateSecretData(rt, `{"password":"p"}`, mode); !errors.Is(err, ErrUnsupportedResourceType) {
				t.Errorf("validateSecretData(mode=%d): expected ErrUnsupportedResourceType, got %v", mode, err)
			}
		}
	}
}

// TestValidateSecretData_StrictAcceptsUnknownNestedField pins the strict definition: only the
// top level is constrained, so nested structures stay open.
func TestValidateSecretData_StrictAcceptsUnknownNestedField(t *testing.T) {
	rt := &api.ResourceType{Slug: "v5-default-with-totp"}
	secret := `{"object_type":"PASSBOLT_SECRET_DATA","password":"p","totp":{"algorithm":"SHA1","secret_key":"k","digits":6,"futureField":"ok"}}`
	if err := validateSecretData(rt, secret, validateWrite); err != nil {
		t.Fatalf("strict write should not constrain nested objects, got %v", err)
	}
}

// Strict mode still enforces declared constraints, and those failures are not ErrSchemaMismatch.
func TestValidateMetadata_StrictEnforcesRequiredAndTypes(t *testing.T) {
	rt := &api.ResourceType{Slug: "v5-default"}
	envelope := `"object_type":"PASSBOLT_RESOURCE_METADATA","resource_type_id":"r"`

	tests := []struct {
		name, metadata string
	}{
		{"missing required name", `{` + envelope + `}`},
		{"name over maxLength", `{"name":"` + strings.Repeat("a", 300) + `",` + envelope + `}`},
		{"wrong type for uris", `{"name":"x","uris":"not-an-array",` + envelope + `}`},
	}
	for _, tc := range tests {
		err := validateMetadata(rt, tc.metadata, validateWrite)
		if err == nil {
			t.Errorf("%s: expected strict validation to fail", tc.name)
			continue
		}
		if errors.Is(err, ErrSchemaMismatch) {
			t.Errorf("%s: a declared-constraint failure must not be classified as ErrSchemaMismatch: %v", tc.name, err)
		}
	}
}

// TestValidateMetadata_StrictUnknownFieldIsSchemaMismatch is the other half: an undeclared
// property is the one case where the bundle may be behind the server, so it carries the sentinel.
func TestValidateMetadata_StrictUnknownFieldIsSchemaMismatch(t *testing.T) {
	rt := &api.ResourceType{Slug: "v5-default"}
	meta := `{"name":"x","object_type":"PASSBOLT_RESOURCE_METADATA","resource_type_id":"r","bogus":"nope"}`

	err := validateMetadata(rt, meta, validateWrite)
	if !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("expected ErrSchemaMismatch, got %v", err)
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error should name the offending property, got %q", err.Error())
	}

	// The same document on the secret side.
	secretErr := validateSecretData(rt, `{"object_type":"PASSBOLT_SECRET_DATA","password":"p","bogus":"x"}`, validateWrite)
	if !errors.Is(secretErr, ErrSchemaMismatch) {
		t.Fatalf("expected ErrSchemaMismatch on the secret path, got %v", secretErr)
	}

	// Lenient mode never classifies, because it never rejects an undeclared property.
	if err := validateMetadata(rt, meta, validateRead); err != nil {
		t.Errorf("lenient read should accept the undeclared property, got %v", err)
	}
}

// compileSection mutates its copy in place; an aliased bundle would make later reads strict.
func TestCompileSection_LeavesBundleUnmutated(t *testing.T) {
	rt := &api.ResourceType{Slug: "v5-default"}

	if _, err := compileSection(rt, schemaSectionResource, validateWrite); err != nil {
		t.Fatalf("compileSection(write): %v", err)
	}

	def, err := rt.Schema()
	if err != nil {
		t.Fatalf("Schema(): %v", err)
	}
	if _, ok := def.Resource["additionalProperties"]; ok {
		t.Error("strict compile leaked additionalProperties into the bundle")
	}
	props := def.Resource["properties"].(map[string]any)
	for _, envelope := range envelopeFields[schemaSectionResource] {
		if _, ok := props[envelope]; ok {
			t.Errorf("strict compile leaked the %q allowExtra stub into the bundle", envelope)
		}
	}

	// The observable consequence: a lenient read must still accept an undeclared property.
	meta := `{"name":"x","object_type":"PASSBOLT_RESOURCE_METADATA","resource_type_id":"r","futureField":"ok"}`
	if err := validateMetadata(rt, meta, validateRead); err != nil {
		t.Errorf("lenient read broken by a previous strict compile: %v", err)
	}
}

// TestCompileSection_ModeAndSectionDoNotShareCache guards the mode component of the cache key in
// both orders: a cache populated by one mode must never serve the other.
func TestCompileSection_ModeAndSectionDoNotShareCache(t *testing.T) {
	meta := `{"name":"x","object_type":"PASSBOLT_RESOURCE_METADATA","resource_type_id":"r","bogus":"nope"}`

	// Read first, then write.
	rt := &api.ResourceType{Slug: "v5-default"}
	if err := validateMetadata(rt, meta, validateRead); err != nil {
		t.Fatalf("lenient read: %v", err)
	}
	if err := validateMetadata(rt, meta, validateWrite); err == nil {
		t.Error("strict write served a cached lenient schema")
	}

	// Write first, then read, on a different slug so both orderings are covered.
	note := &api.ResourceType{Slug: "v5-note"}
	noteMeta := `{"name":"x","object_type":"PASSBOLT_RESOURCE_METADATA","resource_type_id":"r","bogus":"nope"}`
	if err := validateMetadata(note, noteMeta, validateWrite); err == nil {
		t.Error("strict write should reject the undeclared property")
	}
	if err := validateMetadata(note, noteMeta, validateRead); err != nil {
		t.Errorf("lenient read served a cached strict schema: %v", err)
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

	if err := validateSecretData(pinCode, pinSecret, validateWrite); err != nil {
		t.Errorf("v5-pin-code secret rejected: %v", err)
	}
	if err := validateSecretData(def, defSecret, validateWrite); err != nil {
		t.Errorf("v5-default secret rejected (cache collision on the empty ID?): %v", err)
	}
	// And the reverse pairing must fail, proving the two really are distinct schemas.
	if err := validateSecretData(pinCode, defSecret, validateWrite); err == nil {
		t.Error("v5-pin-code accepted a v5-default secret")
	}
}

// TestValidateSecretData_StringSecretLengthFastPath covers the plain-string secret path, which
// cannot go through the JSON validator at all and so is mode-independent.
func TestValidateSecretData_StringSecretLengthFastPath(t *testing.T) {
	rt := &api.ResourceType{Slug: "v5-password-string"}

	for _, mode := range []validationMode{validateRead, validateWrite} {
		if err := validateSecretData(rt, strings.Repeat("a", 4096), mode); err != nil {
			t.Errorf("mode=%d: a 4096-byte password should be accepted, got %v", mode, err)
		}
		if err := validateSecretData(rt, strings.Repeat("a", 4097), mode); !errors.Is(err, ErrPasswordTooLong) {
			t.Errorf("mode=%d: expected ErrPasswordTooLong, got %v", mode, err)
		}
	}
}

// Lenient mode still enforces enums, patterns and limits; those failures carry
// ErrSchemaValidation but not ErrSchemaMismatch.
func TestValidate_LenientStillEnforcesDeclaredConstraints(t *testing.T) {
	rt := &api.ResourceType{Slug: "v5-default"}
	envelope := `"object_type":"PASSBOLT_RESOURCE_METADATA","resource_type_id":"r"`

	tests := []struct {
		name, metadata string
	}{
		// An icon set added after this build shipped.
		{"enum", `{"name":"x",` + envelope + `,"icon":{"type":"material-icon-set","value":1}}`},
		// A color stored without the leading '#'.
		{"pattern", `{"name":"x",` + envelope + `,"icon":{"background_color":"FF00AA"}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMetadata(rt, tc.metadata, validateRead)
			if err == nil {
				t.Fatal("expected the declared constraint to still be enforced on the read path")
			}
			if !errors.Is(err, ErrSchemaValidation) {
				t.Errorf("must carry ErrSchemaValidation, got %v", err)
			}
			if errors.Is(err, ErrSchemaMismatch) {
				t.Error("ErrSchemaMismatch is for undeclared properties on writes only")
			}
		})
	}
}

// TestErrSchemaMismatch_ImpliesSchemaValidation pins the sentinel hierarchy: a caller skipping on
// ErrSchemaValidation must also catch the write-path case.
func TestErrSchemaMismatch_ImpliesSchemaValidation(t *testing.T) {
	if !errors.Is(ErrSchemaMismatch, ErrSchemaValidation) {
		t.Error("ErrSchemaMismatch should wrap ErrSchemaValidation")
	}
	if errors.Is(ErrSchemaValidation, ErrSchemaMismatch) {
		t.Error("the implication must not run the other way")
	}
}

// Strict validation accepts object_type in secrets via the allowlist, not the schema.
func TestValidateSecretData_StrictAcceptsEnvelope(t *testing.T) {
	for _, slug := range []string{"v5-default", "v5-note", "v5-pin-code", "v5-totp-standalone"} {
		rt := &api.ResourceType{Slug: slug}
		def, err := rt.Schema()
		if err != nil {
			t.Fatalf("%s: Schema(): %v", slug, err)
		}
		// Drop object_type from the copy compileSection would see, simulating a release that
		// stops declaring it, and check the allowlist still carries the SDK's own document.
		delete(def.Secret["properties"].(map[string]any), "object_type")
		api.DenyAdditionalProperties(def.Secret, envelopeFields[schemaSectionSecret]...)
		if _, ok := def.Secret["properties"].(map[string]any)["object_type"]; !ok {
			t.Errorf("%s: object_type should stay permitted via envelopeFields", slug)
		}
	}
}

// Every bundled type, not just the ones the tests above name, rejects an undeclared top-level key
// on the write path. This is what keeps a future schema file from being added in a shape that
// DenyAdditionalProperties would leave permissive.
func TestValidate_StrictRejectsUndeclaredKeyForEveryBundledSlug(t *testing.T) {
	for slug := range api.ResourceSchemas {
		t.Run(slug, func(t *testing.T) {
			rt := &api.ResourceType{Slug: slug}
			doc := `{"bogus":"nope"}`

			if err := validateMetadata(rt, doc, validateWrite); !errors.Is(err, ErrSchemaMismatch) {
				t.Errorf("metadata: expected ErrSchemaMismatch for an undeclared key, got %v", err)
			}
			if rt.IsSecretString() {
				return // a plain-string secret has no keys to declare
			}
			if err := validateSecretData(rt, doc, validateWrite); !errors.Is(err, ErrSchemaMismatch) {
				t.Errorf("secret: expected ErrSchemaMismatch for an undeclared key, got %v", err)
			}
		})
	}
}
