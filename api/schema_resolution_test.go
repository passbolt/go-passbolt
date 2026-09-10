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

// TestResourceTypeSchema_ReturnsIndependentCopy guards the copy contract: callers may mutate the
// returned schema in place, so aliasing the bundle would leak those changes into later calls.
func TestResourceTypeSchema_ReturnsIndependentCopy(t *testing.T) {
	rt := &ResourceType{Slug: "v5-default"}

	first, err := rt.Schema()
	if err != nil {
		t.Fatalf("Schema(): %v", err)
	}
	first.Resource["additionalProperties"] = false
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
