package helper

import "testing"

// GetStringField safely extracts a string from a decoded JSON map.
// It has three real branches: missing key, present-but-wrong-type, and
// present-as-string. Callers in resource_get.go rely on the
// "" sentinel for missing/wrong-type to drive defaulting and fallback
// logic — a regression that panicked on a non-string value would
// crash on the first malformed v5 metadata payload.
func TestGetStringField(t *testing.T) {
	t.Parallel()

	m := map[string]any{
		"name":   "alice",
		"empty":  "",
		"number": 42,
		"nilval": nil,
	}

	cases := []struct {
		name string
		key  string
		want string
	}{
		{"present as string", "name", "alice"},
		{"present as empty string", "empty", ""},
		{"present as int (wrong type)", "number", ""},
		{"present as nil (wrong type)", "nilval", ""},
		{"missing key", "absent", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := GetStringField(m, tc.key); got != tc.want {
				t.Errorf("GetStringField(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}
