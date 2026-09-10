package api

// DenyAdditionalProperties sets additionalProperties:false on a schema's top level, in place,
// keeping allowExtra accepted. Nested structures stay open.
//
// It applies to every section, whatever its "type". JSON Schema only evaluates properties and
// additionalProperties against objects, so a string-typed secret is unaffected, and a section that
// omits "type" is still locked down rather than silently left permissive.
func DenyAdditionalProperties(section map[string]any, allowExtra ...string) {
	if section == nil {
		return
	}
	props, ok := section["properties"].(map[string]any)
	if !ok {
		props = map[string]any{}
		section["properties"] = props
	}
	for _, name := range allowExtra {
		if _, exists := props[name]; !exists {
			props[name] = map[string]any{} // empty schema: accept any value
		}
	}
	section["additionalProperties"] = false
}
