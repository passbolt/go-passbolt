package api

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestResourceTypeSchema_IgnoresServerDefinition checks the central premise: for a bundled slug
// the embedded schema is the only source, even when the server sends a conflicting definition.
func TestResourceTypeSchema_IgnoresServerDefinition(t *testing.T) {
	rt := &ResourceType{
		Slug:       "v5-default",
		Definition: json.RawMessage(`{"resource":{"type":"object","properties":{"foo":{"type":"string"}}},"secret":{"type":"object","properties":{}}}`),
	}
	def, err := rt.Schema()
	if err != nil {
		t.Fatalf("Schema(): %v", err)
	}
	props, _ := def.Resource["properties"].(map[string]any)
	if _, ok := props["icon"]; !ok {
		t.Errorf("expected the embedded v5-default schema (which declares 'icon'); got: %v", props)
	}
	if _, ok := props["foo"]; ok {
		t.Error("server Definition must be ignored, but its 'foo' property leaked into the resolved schema")
	}
}

// An unbundled slug is always unavailable, even when the server sent a usable definition.
func TestResourceTypeSchema_UnbundledSlugUnavailable(t *testing.T) {
	validDefinition := `{"resource":{"type":"object","properties":{"foo":{"type":"string"}}},"secret":{"type":"object"}}`
	escaped, err := json.Marshal(validDefinition)
	if err != nil {
		t.Fatalf("marshaling escaped definition: %v", err)
	}

	for _, def := range []string{"", "[]", `"[]"`, validDefinition, string(escaped)} {
		rt := &ResourceType{Slug: "totally-new-type", Definition: json.RawMessage(def)}
		if _, err := rt.Schema(); !errors.Is(err, ErrSchemaUnavailable) {
			t.Errorf("Definition %q: expected ErrSchemaUnavailable, got %v", def, err)
		}
	}

	if HasResourceSchema("totally-new-type") {
		t.Error("HasResourceSchema should be false for an unbundled slug")
	}
	if !HasResourceSchema("v5-default") {
		t.Error("HasResourceSchema should be true for a bundled slug")
	}
}

// TestResourceTypeSchema_ReturnsIndependentCopy guards the copy contract: compileSection mutates
// the returned schema in place, so aliasing the bundle would leak strictness into later reads.
func TestResourceTypeSchema_ReturnsIndependentCopy(t *testing.T) {
	rt := &ResourceType{Slug: "v5-default"}

	first, err := rt.Schema()
	if err != nil {
		t.Fatalf("Schema(): %v", err)
	}
	DenyAdditionalProperties(first.Resource)
	delete(first.Resource["properties"].(map[string]any), "name")

	second, err := rt.Schema()
	if err != nil {
		t.Fatalf("Schema() second call: %v", err)
	}
	if _, ok := second.Resource["additionalProperties"]; ok {
		t.Error("mutation of the first copy leaked into the bundle: additionalProperties is set")
	}
	if props := second.Resource["properties"].(map[string]any); props["name"] == nil {
		t.Error("mutation of the first copy leaked into the bundle: 'name' was deleted")
	}
}

func TestDenyAdditionalProperties(t *testing.T) {
	// Object schema is locked down and allowExtra fields are whitelisted.
	obj := map[string]any{
		"type":       "object",
		"properties": map[string]any{"name": map[string]any{"type": "string"}},
	}
	DenyAdditionalProperties(obj, "object_type")
	if obj["additionalProperties"] != false {
		t.Errorf("expected additionalProperties=false, got %v", obj["additionalProperties"])
	}
	if props := obj["properties"].(map[string]any); props["object_type"] == nil {
		t.Error("allowExtra field 'object_type' not added to properties")
	}

	// A section that omits "type" is still locked down; leaving it open would turn strict
	// validation into lenient validation for that type without anyone noticing.
	untyped := map[string]any{"properties": map[string]any{"name": map[string]any{"type": "string"}}}
	DenyAdditionalProperties(untyped)
	if untyped["additionalProperties"] != false {
		t.Error("a section without \"type\" should be locked down")
	}

	// A section without properties gets an empty map so the allowExtra stubs have a home.
	bare := map[string]any{"type": "object"}
	DenyAdditionalProperties(bare, "object_type")
	if props := bare["properties"].(map[string]any); props["object_type"] == nil {
		t.Error("allowExtra field 'object_type' not added to a section without properties")
	}
}

// TestDenyAdditionalProperties_DoesNotRecurse pins the strict definition: only the top-level node
// is constrained, so nested structures (totp, custom_fields entries, icon) stay open.
func TestDenyAdditionalProperties_DoesNotRecurse(t *testing.T) {
	rt := &ResourceType{Slug: "v5-default-with-totp"}
	def, err := rt.Schema()
	if err != nil {
		t.Fatalf("Schema(): %v", err)
	}

	DenyAdditionalProperties(def.Secret, "object_type")
	if def.Secret["additionalProperties"] != false {
		t.Fatal("top-level secret schema should have been locked down")
	}

	secretProps := def.Secret["properties"].(map[string]any)
	for _, nested := range []string{"totp", "custom_fields"} {
		node, ok := secretProps[nested].(map[string]any)
		if !ok {
			t.Fatalf("v5-default-with-totp secret should declare %q", nested)
		}
		if _, set := node["additionalProperties"]; set {
			t.Errorf("%q must not be constrained: DenyAdditionalProperties does not recurse", nested)
		}
	}

	DenyAdditionalProperties(def.Resource, "object_type", "resource_type_id")
	icon, ok := def.Resource["properties"].(map[string]any)["icon"].(map[string]any)
	if !ok {
		t.Fatal("v5-default-with-totp resource should declare 'icon'")
	}
	if _, set := icon["additionalProperties"]; set {
		t.Error("'icon' must not be constrained: DenyAdditionalProperties does not recurse")
	}
}
