package api

import (
	"embed"
	"encoding/json"
	"strings"
)

// schemaFS holds the resource-type definitions this SDK validates against, copied verbatim from
// passbolt_api, plugins/PassboltCe/ResourceTypes/src/Model/Definition/SlugDefinition.php. They
// are authoritative: the definition a server reports is never used. See ResourceType.Schema.
//
// To add or update one, drop a <slug>.json file in schemas/ holding that type's "definition"
// exactly as the API returns it. The name minus ".json" is the slug key. No Go changes needed.
//
//go:embed schemas/*.json
var schemaFS embed.FS

// ResourceSchemas maps a resource-type slug to its definition JSON. Not API stable! Prefer
// ResourceType.Schema, which returns a copy callers may modify.
var ResourceSchemas = loadResourceSchemas()

// parsedSchemas holds one decoded copy of every bundled schema. The read-only predicates on
// ResourceType share it, so a lookup costs a map access rather than a JSON parse on every call.
// Schema returns a fresh copy instead, because callers may modify what they get.
var parsedSchemas = parseResourceSchemas()

// HasResourceSchema reports whether this SDK bundles a schema for the given slug. Callers that
// process many resources can use it to skip unsupported ones up front.
func HasResourceSchema(slug string) bool {
	_, ok := ResourceSchemas[slug]
	return ok
}

func loadResourceSchemas() map[string]json.RawMessage {
	entries, err := schemaFS.ReadDir("schemas")
	if err != nil {
		panic("api: reading embedded schemas: " + err.Error())
	}
	m := make(map[string]json.RawMessage, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := schemaFS.ReadFile("schemas/" + e.Name())
		if err != nil {
			panic("api: reading embedded schema " + e.Name() + ": " + err.Error())
		}
		m[strings.TrimSuffix(e.Name(), ".json")] = json.RawMessage(data)
	}
	return m
}

func parseResourceSchemas() map[string]*ResourceTypeSchema {
	m := make(map[string]*ResourceTypeSchema, len(ResourceSchemas))
	for slug, raw := range ResourceSchemas {
		var schema ResourceTypeSchema
		if err := json.Unmarshal(raw, &schema); err != nil {
			panic("api: parsing embedded schema " + slug + ": " + err.Error())
		}
		m[slug] = &schema
	}
	return m
}
