package helper

import (
	"errors"
	"reflect"
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
		metadata = map[string]any{
			"id":           id,
			"metadata_key": "field-name",
		}
		secret = map[string]any{
			"id":           id,
			"secret_value": "field-value",
		}
		return metadata, secret
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

// ParseCustomFields is the read counterpart of validateCustomFields: it
// projects whatever the server returned, and must never error, because a
// single malformed field would otherwise make a whole resource unreadable.
// The rows below pin the two rules that are easy to get subtly wrong: which
// side owns the name, and which side owns the value.
func Test_ParseCustomFields(t *testing.T) {
	t.Parallel()

	const idA = "11111111-1111-1111-1111-111111111111"
	const idB = "22222222-2222-2222-2222-222222222222"

	cases := []struct {
		name     string
		metadata map[string]any
		secret   map[string]any
		want     CustomFields
	}{
		{
			name:     "no custom_fields in metadata",
			metadata: map[string]any{"name": "x"},
			secret:   map[string]any{"password": "p"},
			want:     nil,
		},
		{
			name:     "empty custom_fields array",
			metadata: map[string]any{"custom_fields": []any{}},
			secret:   map[string]any{},
			want:     nil,
		},
		{
			name:     "secret-only custom_fields are ignored: metadata is the spine",
			metadata: map[string]any{"name": "x"},
			secret: map[string]any{
				"custom_fields": []any{map[string]any{"id": idA, "secret_value": "v"}},
			},
			want: nil,
		},
		{
			name: "standard case: metadata_key with secret_value",
			metadata: map[string]any{
				"custom_fields": []any{map[string]any{"id": idA, "metadata_key": "api-key"}},
			},
			secret: map[string]any{
				"custom_fields": []any{map[string]any{"id": idA, "secret_value": "secret-123"}},
			},
			want: CustomFields{{ID: idA, Name: "api-key", Value: "secret-123"}},
		},
		{
			// The shape a cleartext field must take: validateCustomFields requires
			// the secret_value key to exist, so it is present but empty. Keying on
			// presence rather than emptiness would report "" for this field.
			name: "cleartext field: metadata_value wins over an empty secret_value",
			metadata: map[string]any{
				"custom_fields": []any{
					map[string]any{"id": idA, "metadata_key": "env", "metadata_value": "production"},
				},
			},
			secret: map[string]any{
				"custom_fields": []any{map[string]any{"id": idA, "secret_value": ""}},
			},
			want: CustomFields{{ID: idA, Name: "env", Value: "production"}},
		},
		{
			name: "secret_value takes precedence over metadata_value",
			metadata: map[string]any{
				"custom_fields": []any{
					map[string]any{"id": idA, "metadata_key": "field", "metadata_value": "meta-val"},
				},
			},
			secret: map[string]any{
				"custom_fields": []any{map[string]any{"id": idA, "secret_value": "secret-val"}},
			},
			want: CustomFields{{ID: idA, Name: "field", Value: "secret-val"}},
		},
		{
			name: "empty secret_value with no metadata_value stays empty",
			metadata: map[string]any{
				"custom_fields": []any{map[string]any{"id": idA, "metadata_key": "empty-field"}},
			},
			secret: map[string]any{
				"custom_fields": []any{map[string]any{"id": idA, "secret_value": ""}},
			},
			want: CustomFields{{ID: idA, Name: "empty-field", Value: ""}},
		},
		{
			// metadata_key present but empty plus secret_key set is a valid shape:
			// the cross-field check only rejects a name on both sides at once.
			name: "encrypted name resolves from secret_key",
			metadata: map[string]any{
				"custom_fields": []any{map[string]any{"id": idA, "metadata_key": ""}},
			},
			secret: map[string]any{
				"custom_fields": []any{
					map[string]any{"id": idA, "secret_key": "hidden-name", "secret_value": "hidden-val"},
				},
			},
			want: CustomFields{{ID: idA, Name: "hidden-name", Value: "hidden-val"}},
		},
		{
			name: "order follows the metadata array, not the secret array",
			metadata: map[string]any{
				"custom_fields": []any{
					map[string]any{"id": idA, "metadata_key": "token"},
					map[string]any{"id": idB, "metadata_key": "region", "metadata_value": "us-east-1"},
				},
			},
			secret: map[string]any{
				"custom_fields": []any{
					map[string]any{"id": idB, "secret_value": ""},
					map[string]any{"id": idA, "secret_value": "tok-abc123"},
				},
			},
			want: CustomFields{
				{ID: idA, Name: "token", Value: "tok-abc123"},
				{ID: idB, Name: "region", Value: "us-east-1"},
			},
		},
		{
			name: "numeric and boolean values are stringified",
			metadata: map[string]any{
				"custom_fields": []any{
					map[string]any{"id": idA, "metadata_key": "port"},
					map[string]any{"id": idB, "metadata_key": "enabled", "metadata_value": true},
				},
			},
			secret: map[string]any{
				"custom_fields": []any{
					map[string]any{"id": idA, "secret_value": float64(8080)},
					map[string]any{"id": idB, "secret_value": ""},
				},
			},
			want: CustomFields{
				{ID: idA, Name: "port", Value: "8080"},
				{ID: idB, Name: "enabled", Value: "true"},
			},
		},
		{
			name: "metadata id with no matching secret entry falls back to metadata_value",
			metadata: map[string]any{
				"custom_fields": []any{
					map[string]any{"id": idA, "metadata_key": "orphan", "metadata_value": "kept"},
				},
			},
			secret: map[string]any{"custom_fields": []any{}},
			want:   CustomFields{{ID: idA, Name: "orphan", Value: "kept"}},
		},
		{
			name: "metadata entry with no id is unmatchable",
			metadata: map[string]any{
				"custom_fields": []any{
					map[string]any{"metadata_key": "no-id", "metadata_value": "meta"},
				},
			},
			secret: map[string]any{
				"custom_fields": []any{map[string]any{"id": idA, "secret_value": "unreachable"}},
			},
			want: CustomFields{{ID: "", Name: "no-id", Value: "meta"}},
		},
		{
			name: "duplicate id in metadata keeps both entries",
			metadata: map[string]any{
				"custom_fields": []any{
					map[string]any{"id": idA, "metadata_key": "first"},
					map[string]any{"id": idA, "metadata_key": "second"},
				},
			},
			secret: map[string]any{
				"custom_fields": []any{map[string]any{"id": idA, "secret_value": "shared"}},
			},
			want: CustomFields{
				{ID: idA, Name: "first", Value: "shared"},
				{ID: idA, Name: "second", Value: "shared"},
			},
		},
		{
			name: "duplicate id in secret: last occurrence wins",
			metadata: map[string]any{
				"custom_fields": []any{map[string]any{"id": idA, "metadata_key": "k"}},
			},
			secret: map[string]any{
				"custom_fields": []any{
					map[string]any{"id": idA, "secret_value": "first"},
					map[string]any{"id": idA, "secret_value": "last"},
				},
			},
			want: CustomFields{{ID: idA, Name: "k", Value: "last"}},
		},
		{
			// Malformed input only: uuid ids plus the uniqueness rules in the web
			// extension and validateCustomFields keep any compliant writer from
			// producing this. Both rules then apply at once: every metadata entry is
			// kept, and each resolves against the one surviving secret entry for that
			// id. The id is the only correlation the format defines, so there is
			// nothing to pair "first" with "a" by.
			name: "duplicate id on both sides",
			metadata: map[string]any{
				"custom_fields": []any{
					map[string]any{"id": idA, "metadata_key": "first"},
					map[string]any{"id": idA, "metadata_key": "second"},
				},
			},
			secret: map[string]any{
				"custom_fields": []any{
					map[string]any{"id": idA, "secret_value": "a"},
					map[string]any{"id": idA, "secret_value": "b"},
				},
			},
			want: CustomFields{
				{ID: idA, Name: "first", Value: "b"},
				{ID: idA, Name: "second", Value: "b"},
			},
		},
		{
			name:     "custom_fields is not an array",
			metadata: map[string]any{"custom_fields": "nope"},
			secret:   map[string]any{"custom_fields": 42},
			want:     nil,
		},
		{
			name: "non-map array items are skipped",
			metadata: map[string]any{
				"custom_fields": []any{
					"garbage",
					map[string]any{"id": idA, "metadata_key": "k", "metadata_value": "v"},
				},
			},
			secret: map[string]any{"custom_fields": []any{nil, 7}},
			want:   CustomFields{{ID: idA, Name: "k", Value: "v"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ParseCustomFields(tc.metadata, tc.secret)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseCustomFields() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func Test_CustomFields_Map(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   CustomFields
		want map[string]string
	}{
		{name: "nil slice", in: nil, want: map[string]string{}},
		{name: "empty slice", in: CustomFields{}, want: map[string]string{}},
		{
			name: "unnamed fields are dropped",
			in:   CustomFields{{ID: "a", Name: "", Value: "v"}},
			want: map[string]string{},
		},
		{
			name: "named fields survive, unnamed are skipped",
			in: CustomFields{
				{ID: "a", Name: "k1", Value: "v1"},
				{ID: "b", Name: "", Value: "dropped"},
				{ID: "c", Name: "k2", Value: ""},
			},
			want: map[string]string{"k1": "v1", "k2": ""},
		},
		{
			name: "duplicate names: last occurrence wins",
			in: CustomFields{
				{ID: "a", Name: "dup", Value: "first"},
				{ID: "b", Name: "dup", Value: "last"},
			},
			want: map[string]string{"dup": "last"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.in.Map(); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Map() = %v, want %v", got, tc.want)
			}
		})
	}
}

// metadata_value and secret_value are schema-untyped, so a custom field value
// arrives as whatever json.Unmarshal produced. Every branch here is a value a
// server can legitimately return.
func Test_stringifyCustomFieldValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   any
		want string
	}{
		{name: "nil", in: nil, want: ""},
		{name: "empty string", in: "", want: ""},
		{name: "string", in: "x", want: "x"},
		{name: "true", in: true, want: "true"},
		{name: "false", in: false, want: "false"},
		{name: "integral float64", in: float64(8080), want: "8080"},
		{name: "fractional float64", in: float64(1.5), want: "1.5"},
		{name: "large float64 is not rendered in exponent form", in: 1e21, want: "1000000000000000000000"},
		{name: "native int", in: 42, want: "42"},
		{name: "nested object", in: map[string]any{"k": "v"}, want: "map[k:v]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := stringifyCustomFieldValue(tc.in); got != tc.want {
				t.Errorf("stringifyCustomFieldValue(%#v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
