package helper

import (
	"fmt"

	"github.com/google/uuid"
)

// validateCustomFields validates custom_fields arrays in metadata and secret maps
// before encryption. This enforces the same rules as the Passbolt web extension:
//   - Every custom field id must be a valid UUID
//   - Every custom field id must appear in both metadata and secret arrays
//   - metadata entries must have metadata_key
//   - secret entries must have secret_value
//   - key/value must not be defined on both sides for the same field id
//
// Returns nil if neither map contains custom_fields (not a custom fields resource).
func validateCustomFields(metadataFields, secretFields map[string]any) error {
	metaCF, metaOK := extractCustomFields(metadataFields)
	secretCF, secretOK := extractCustomFields(secretFields)

	// Not a custom fields resource
	if !metaOK && !secretOK {
		return nil
	}

	// If one side has custom_fields, the other must too
	if metaOK != secretOK {
		return fmt.Errorf("%w: custom_fields present in one side but not the other", ErrCustomFieldIDMismatch)
	}

	// Build indexes by id
	metaByID := make(map[string]map[string]any, len(metaCF))
	for i, cf := range metaCF {
		id, ok := cf["id"].(string)
		if !ok || id == "" {
			return fmt.Errorf("%w: metadata custom_fields[%d] has no id", ErrCustomFieldInvalidID, i)
		}
		if _, err := uuid.Parse(id); err != nil {
			return fmt.Errorf("%w: %q (metadata custom_fields[%d])", ErrCustomFieldInvalidID, id, i)
		}
		if _, exists := metaByID[id]; exists {
			return fmt.Errorf("%w: duplicate id %q in metadata custom_fields", ErrCustomFieldInvalidID, id)
		}
		metaByID[id] = cf
	}

	secretByID := make(map[string]map[string]any, len(secretCF))
	for i, cf := range secretCF {
		id, ok := cf["id"].(string)
		if !ok || id == "" {
			return fmt.Errorf("%w: secret custom_fields[%d] has no id", ErrCustomFieldInvalidID, i)
		}
		if _, err := uuid.Parse(id); err != nil {
			return fmt.Errorf("%w: %q (secret custom_fields[%d])", ErrCustomFieldInvalidID, id, i)
		}
		if _, exists := secretByID[id]; exists {
			return fmt.Errorf("%w: duplicate id %q in secret custom_fields", ErrCustomFieldInvalidID, id)
		}
		secretByID[id] = cf
	}

	// Strict: every id must appear in both arrays
	if len(metaByID) != len(secretByID) {
		return fmt.Errorf("%w: metadata has %d fields, secret has %d", ErrCustomFieldIDMismatch, len(metaByID), len(secretByID))
	}
	for id := range metaByID {
		if _, ok := secretByID[id]; !ok {
			return fmt.Errorf("%w: id %q is in metadata but not in secret", ErrCustomFieldIDMismatch, id)
		}
	}

	// Validate each field
	for id, metaEntry := range metaByID {
		secretEntry := secretByID[id]

		// metadata entry must have metadata_key
		if _, ok := metaEntry["metadata_key"]; !ok {
			return fmt.Errorf("%w: id %q", ErrCustomFieldMissingKey, id)
		}

		// secret entry must have secret_value
		if _, ok := secretEntry["secret_value"]; !ok {
			return fmt.Errorf("%w: id %q", ErrCustomFieldMissingValue, id)
		}

		// Cross-field: key must be on one side only
		metaHasKey := hasNonEmptyString(metaEntry, "metadata_key")
		secretHasKey := hasNonEmptyString(secretEntry, "secret_key")
		if metaHasKey && secretHasKey {
			return fmt.Errorf("%w: id %q has both metadata_key and secret_key", ErrCustomFieldCrossField, id)
		}

		// Cross-field: value must be on one side only
		metaHasValue := hasNonEmptyString(metaEntry, "metadata_value")
		secretHasValue := hasNonEmptyString(secretEntry, "secret_value")
		if metaHasValue && secretHasValue {
			return fmt.Errorf("%w: id %q has both metadata_value and secret_value", ErrCustomFieldCrossField, id)
		}
	}

	return nil
}

// extractCustomFields extracts the custom_fields array from a field map.
func extractCustomFields(fields map[string]any) ([]map[string]any, bool) {
	raw, ok := fields["custom_fields"]
	if !ok {
		return nil, false
	}
	arr, ok := raw.([]any)
	if !ok {
		// Already typed as []map[string]any (unlikely from JSON but handle it)
		if typed, ok := raw.([]map[string]any); ok {
			return typed, true
		}
		return nil, false
	}
	result := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			result = append(result, m)
		}
	}
	return result, len(result) > 0
}

// hasNonEmptyString checks if a map entry exists and is a non-empty string.
func hasNonEmptyString(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	s, ok := v.(string)
	return ok && s != ""
}
