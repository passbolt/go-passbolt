package helper

import (
	"errors"
	"testing"
)

// validateCustomFields is security-critical: it enforces the same
// invariants on custom_fields that the Passbolt web extension does,
// before the metadata is encrypted (the server can't validate
// encrypted content). Every branch below is a real defense — if any
// regressed, a caller could ship a malformed or contradictory payload
// that the server would persist but no client could decrypt back into
// a coherent shape.
//
// The test is one large table-driven case set so adding a new
// invariant is a one-line addition.

func Test_validateCustomFields(t *testing.T) {
	t.Parallel()

	const idA = "11111111-1111-1111-1111-111111111111"
	const idB = "22222222-2222-2222-2222-222222222222"

	// validEntry builds a minimal pair (metadata + secret) of custom
	// field entries for the given id. Each test starts from this
	// shape and mutates exactly the field under test.
	validEntry := func(id string) (metadata, secret map[string]any) {
		return map[string]any{
				"id":           id,
				"metadata_key": "field-name",
			}, map[string]any{
				"id":           id,
				"secret_value": "field-value",
			}
	}

	cases := []struct {
		name     string
		metadata map[string]any
		secret   map[string]any
		wantErr  error // nil for happy path; otherwise the sentinel returned must wrap this
	}{
		{
			name:     "no custom_fields on either side is allowed (not a custom-fields resource)",
			metadata: map[string]any{"name": "x"},
			secret:   map[string]any{"password": "p"},
			wantErr:  nil,
		},
		{
			name: "happy path: one symmetric pair",
			metadata: func() map[string]any {
				m, _ := validEntry(idA)
				return map[string]any{"custom_fields": []any{m}}
			}(),
			secret: func() map[string]any {
				_, s := validEntry(idA)
				return map[string]any{"custom_fields": []any{s}}
			}(),
			wantErr: nil,
		},
		{
			// Catches an early-break in the per-entry validation
			// loop: with only one pair, an early-return after the
			// first iteration would still produce nil. Two valid
			// pairs force the loop to run twice.
			name: "happy path: two symmetric pairs both valid",
			metadata: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "metadata_key": "k1"},
				map[string]any{"id": idB, "metadata_key": "k2"},
			}},
			secret: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "secret_value": "v1"},
				map[string]any{"id": idB, "secret_value": "v2"},
			}},
			wantErr: nil,
		},
		{
			name: "custom_fields on metadata side only",
			metadata: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "metadata_key": "k"},
			}},
			secret:  map[string]any{},
			wantErr: ErrCustomFieldIDMismatch,
		},
		{
			name:     "custom_fields on secret side only",
			metadata: map[string]any{},
			secret: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "secret_value": "v"},
			}},
			wantErr: ErrCustomFieldIDMismatch,
		},
		{
			name: "invalid UUID in metadata entry id",
			metadata: map[string]any{"custom_fields": []any{
				map[string]any{"id": "not-a-uuid", "metadata_key": "k"},
			}},
			secret: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "secret_value": "v"},
			}},
			wantErr: ErrCustomFieldInvalidID,
		},
		{
			name: "invalid UUID in secret entry id",
			metadata: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "metadata_key": "k"},
			}},
			secret: map[string]any{"custom_fields": []any{
				map[string]any{"id": "not-a-uuid", "secret_value": "v"},
			}},
			wantErr: ErrCustomFieldInvalidID,
		},
		{
			name: "id is not a string type",
			metadata: map[string]any{"custom_fields": []any{
				map[string]any{"id": 123, "metadata_key": "k"},
			}},
			secret: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "secret_value": "v"},
			}},
			wantErr: ErrCustomFieldInvalidID,
		},
		{
			name: "duplicate id in metadata array",
			metadata: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "metadata_key": "k1"},
				map[string]any{"id": idA, "metadata_key": "k2"},
			}},
			secret: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "secret_value": "v"},
			}},
			wantErr: ErrCustomFieldInvalidID,
		},
		{
			name: "duplicate id in secret array",
			metadata: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "metadata_key": "k"},
			}},
			secret: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "secret_value": "v1"},
				map[string]any{"id": idA, "secret_value": "v2"},
			}},
			wantErr: ErrCustomFieldInvalidID,
		},
		{
			name: "asymmetric ids: metadata has id, secret doesn't",
			metadata: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "metadata_key": "k"},
			}},
			secret: map[string]any{"custom_fields": []any{
				map[string]any{"id": idB, "secret_value": "v"},
			}},
			wantErr: ErrCustomFieldIDMismatch,
		},
		{
			name: "length mismatch: metadata has more entries",
			metadata: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "metadata_key": "k1"},
				map[string]any{"id": idB, "metadata_key": "k2"},
			}},
			secret: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "secret_value": "v"},
			}},
			wantErr: ErrCustomFieldIDMismatch,
		},
		{
			name: "metadata entry missing metadata_key",
			metadata: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA}, // no metadata_key
			}},
			secret: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "secret_value": "v"},
			}},
			wantErr: ErrCustomFieldMissingKey,
		},
		{
			name: "secret entry missing secret_value",
			metadata: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "metadata_key": "k"},
			}},
			secret: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA}, // no secret_value
			}},
			wantErr: ErrCustomFieldMissingValue,
		},
		{
			name: "key defined on both sides (cross-field conflict)",
			metadata: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "metadata_key": "non-empty"},
			}},
			secret: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "secret_value": "v", "secret_key": "non-empty"},
			}},
			wantErr: ErrCustomFieldCrossField,
		},
		{
			name: "value defined on both sides (cross-field conflict)",
			metadata: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "metadata_key": "k", "metadata_value": "non-empty"},
			}},
			secret: map[string]any{"custom_fields": []any{
				map[string]any{"id": idA, "secret_value": "non-empty"},
			}},
			wantErr: ErrCustomFieldCrossField,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateCustomFields(tc.metadata, tc.secret)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("expected nil error, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want wrap of %v", err, tc.wantErr)
			}
		})
	}
}

// extractCustomFields must accept the two shapes that can actually
// arrive in practice: []any (the result of decoding arbitrary JSON
// into map[string]any) and []map[string]any (callers building maps
// programmatically). Failing on either would block valid custom-field
// payloads from being validated.
func Test_extractCustomFields_AcceptsBothShapes(t *testing.T) {
	t.Parallel()

	// []any from json.Unmarshal
	fromJSON, ok := extractCustomFields(map[string]any{
		"custom_fields": []any{
			map[string]any{"id": "a"},
			map[string]any{"id": "b"},
		},
	})
	if !ok || len(fromJSON) != 2 {
		t.Errorf("[]any shape: got %d entries (ok=%v), want 2", len(fromJSON), ok)
	}

	// Pre-typed []map[string]any
	fromTyped, ok := extractCustomFields(map[string]any{
		"custom_fields": []map[string]any{
			{"id": "a"},
			{"id": "b"},
		},
	})
	if !ok || len(fromTyped) != 2 {
		t.Errorf("[]map[string]any shape: got %d entries (ok=%v), want 2", len(fromTyped), ok)
	}

	// Absent key returns (nil, false)
	got, ok := extractCustomFields(map[string]any{})
	if ok || got != nil {
		t.Errorf("absent key: got (%v, %v), want (nil, false)", got, ok)
	}
}

// hasNonEmptyString underpins the cross-field-conflict check. The
// distinction between "key absent", "key present as wrong type",
// "key present as empty string", and "key present as non-empty
// string" all branch into different validation outcomes, so each
// must be tested explicitly.
func Test_hasNonEmptyString(t *testing.T) {
	t.Parallel()

	m := map[string]any{
		"present-and-nonempty": "abc",
		"present-but-empty":    "",
		"wrong-type":           42,
	}

	cases := []struct {
		key  string
		want bool
	}{
		{"present-and-nonempty", true},
		{"present-but-empty", false},
		{"wrong-type", false},
		{"absent", false},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			t.Parallel()
			if got := hasNonEmptyString(m, tc.key); got != tc.want {
				t.Errorf("hasNonEmptyString(%q) = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}
