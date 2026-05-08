package api

import (
	"encoding/json"
	"testing"
)

func TestResourceJsonSchema(t *testing.T) {
	for slug, schema := range ResourceSchemas {
		var schemaDefinition ResourceTypeSchema
		err := json.Unmarshal(schema, &schemaDefinition)
		if err != nil {
			t.Errorf("Error While Parsing Resource Schema %v: %v", slug, err)
		} else {
			t.Logf("Schema for type %v is ok", slug)
		}
	}
}
