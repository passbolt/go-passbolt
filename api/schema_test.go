package api

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Every bundled schema has both sections and compiles as standard JSON Schema.
func TestResourceSchemas_AllCompile(t *testing.T) {
	if len(ResourceSchemas) == 0 {
		t.Fatal("no bundled schemas were loaded")
	}
	for slug, raw := range ResourceSchemas {
		var def ResourceTypeSchema
		if err := json.Unmarshal(raw, &def); err != nil {
			t.Errorf("%s: invalid JSON: %v", slug, err)
			continue
		}
		if len(def.Resource) == 0 {
			t.Errorf("%s: empty resource schema", slug)
		}
		if len(def.Secret) == 0 {
			t.Errorf("%s: empty secret schema", slug)
		}

		for name, section := range map[string]map[string]any{"resource": def.Resource, "secret": def.Secret} {
			comp := jsonschema.NewCompiler()
			if err := comp.AddResource("urn:test", section); err != nil {
				t.Errorf("%s/%s: add resource: %v", slug, name, err)
				continue
			}
			if _, err := comp.Compile("urn:test"); err != nil {
				t.Errorf("%s/%s: compile: %v", slug, name, err)
			}
		}
	}
}

// The bundled v5-default accepts an icon object and explicit nulls (the anyOf/null idiom).
func TestResourceSchemas_AcceptIconAndNulls(t *testing.T) {
	raw := ResourceSchemas["v5-default"]
	var def ResourceTypeSchema
	if err := json.Unmarshal(raw, &def); err != nil {
		t.Fatalf("unmarshal v5-default: %v", err)
	}
	comp := jsonschema.NewCompiler()
	if err := comp.AddResource("urn:test", def.Resource); err != nil {
		t.Fatalf("add resource: %v", err)
	}
	schema, err := comp.Compile("urn:test")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	metadata := `{
		"object_type": "PASSBOLT_RESOURCE_METADATA",
		"name": "example",
		"username": null,
		"description": null,
		"uris": ["https://example.com"],
		"icon": {"type": "keepass-icon-set", "value": 12, "background_color": "#FF00AA"}
	}`
	var parsed map[string]any
	if err := json.Unmarshal([]byte(metadata), &parsed); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if err := schema.Validate(parsed); err != nil {
		t.Errorf("v5-default rejected valid icon/null metadata: %v", err)
	}
}

// No bundled schema may ship additionalProperties:false; strictness comes only from
// DenyAdditionalProperties on the write path, or reads would turn strict too.
func TestResourceSchemas_NoBakedAdditionalProperties(t *testing.T) {
	for slug, raw := range ResourceSchemas {
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Errorf("%s: invalid JSON: %v", slug, err)
			continue
		}
		if path := findKey(doc, "additionalProperties", ""); path != "" {
			t.Errorf("%s: schema declares additionalProperties at %s; strictness must come only "+
				"from DenyAdditionalProperties on the write path", slug, path)
		}
	}
}

// TestResourceSchemas_NoRefs guards a limitation of compileSection: it uses a bare compiler with
// one AddResource, so a "$ref" has nothing to resolve against and would fail at runtime.
func TestResourceSchemas_NoRefs(t *testing.T) {
	for slug, raw := range ResourceSchemas {
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			continue // reported by TestResourceSchemas_NoBakedAdditionalProperties
		}
		if path := findKey(doc, "$ref", ""); path != "" {
			t.Errorf("%s: schema uses $ref at %s; compileSection cannot resolve references", slug, path)
		}
	}
}

// findKey walks a decoded JSON document and returns the JSON-Pointer path of the first
// occurrence of want, or "" if it never appears.
func findKey(node any, want, path string) string {
	switch n := node.(type) {
	case map[string]any:
		if _, ok := n[want]; ok {
			return path + "/" + want
		}
		for k, v := range n {
			if found := findKey(v, want, path+"/"+k); found != "" {
				return found
			}
		}
	case []any:
		for i, v := range n {
			if found := findKey(v, want, fmt.Sprintf("%s/%d", path, i)); found != "" {
				return found
			}
		}
	}
	return ""
}

// The bundle stays standard JSON Schema: no OpenAPI "nullable" and only string-valued "type",
// since both would compile cleanly and then silently stop enforcing anything.
func TestResourceSchemas_IsStandardJSONSchema(t *testing.T) {
	for slug, raw := range ResourceSchemas {
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Errorf("%s: invalid JSON: %v", slug, err)
			continue
		}

		if path := findKey(doc, "nullable", ""); path != "" {
			t.Errorf("%s: OpenAPI-style \"nullable\" at %s; express nullability as "+
				`anyOf: [{...}, {"type": "null"}]`, slug, path)
		}
		for _, path := range nonStringTypes(doc, "") {
			t.Errorf("%s: %s is not a string or array of strings", slug, path)
		}
	}
}

// nonStringTypes returns the JSON-Pointer path of every "type" whose value a strict validator
// would reject. Only schema positions are inspected, so a property named "type" is not flagged.
func nonStringTypes(node any, path string) []string {
	var bad []string
	switch n := node.(type) {
	case map[string]any:
		if t, ok := n["type"]; ok && !isTypeValue(t) {
			bad = append(bad, path+"/type")
		}
		for key, value := range n {
			// "properties" maps names to schemas, so its keys are data, not keywords.
			if members, ok := value.(map[string]any); ok && key == "properties" {
				for name, member := range members {
					bad = append(bad, nonStringTypes(member, fmt.Sprintf("%s/properties/%s", path, name))...)
				}
				continue
			}
			bad = append(bad, nonStringTypes(value, path+"/"+key)...)
		}
	case []any:
		for i, v := range n {
			bad = append(bad, nonStringTypes(v, fmt.Sprintf("%s/%d", path, i))...)
		}
	}
	return bad
}

func isTypeValue(t any) bool {
	switch v := t.(type) {
	case string:
		return true
	case []any:
		for _, e := range v {
			if _, ok := e.(string); !ok {
				return false
			}
		}
		return true
	}
	return false
}
