package helper

import (
	"encoding/json"
	"testing"
)

// FuzzValidateCustomFields drives the custom-fields validator with arbitrary
// decoded-JSON shapes. The function and its helpers do a long chain of unchecked
// type assertions on `any` (cf["id"].(string), raw.([]any), item.(map[string]any),
// ...), which is the real panic surface here — a fuzzer that hands it the "wrong"
// type at each step is exactly what flushes those out. Invariant: for any pair of
// JSON objects it must return (an error or nil) without panicking.
func FuzzValidateCustomFields(f *testing.F) {
	valid := `{"custom_fields":[{"id":"11111111-1111-1111-1111-111111111111","metadata_key":"k"}]}`
	validSecret := `{"custom_fields":[{"id":"11111111-1111-1111-1111-111111111111","secret_value":"v"}]}`
	f.Add([]byte(valid), []byte(validSecret))
	f.Add([]byte(`{}`), []byte(`{}`))
	f.Add([]byte(`{"custom_fields":[]}`), []byte(`{}`))
	f.Add([]byte(`{"custom_fields":[{"id":123}]}`), []byte(`{"custom_fields":[{"id":null}]}`))
	f.Add([]byte(`{"custom_fields":"not-an-array"}`), []byte(`{"custom_fields":{}}`))

	f.Fuzz(func(t *testing.T, metaJSON, secretJSON []byte) {
		var meta, secret map[string]any
		if json.Unmarshal(metaJSON, &meta) != nil {
			return
		}
		if json.Unmarshal(secretJSON, &secret) != nil {
			return
		}
		// Property under test: never panics on arbitrary map shapes.
		_ = validateCustomFields(meta, secret)
	})
}
