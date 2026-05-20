package api

import "testing"

// TestServerPassboltSettings_IsPluginEnabled is the load-bearing
// helper used during Login() to gate v5 features. It has two
// branches: missing key (must return false, not crash on nil) and
// present key (return the Enabled flag). Both are exercised here,
// including the negative path that's most likely to regress (e.g. a
// refactor returning true on missing).
func TestServerPassboltSettings_IsPluginEnabled(t *testing.T) {
	t.Parallel()

	settings := ServerPassboltSettings{
		Plugins: map[string]ServerPassboltPluginSettings{
			"metadata": {Enabled: true},
			"mfa":      {Enabled: false},
		},
	}
	cases := []struct {
		name string
		want bool
	}{
		{"metadata", true},
		{"mfa", false},
		{"nonexistent", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := settings.IsPluginEnabled(tc.name); got != tc.want {
				t.Errorf("IsPluginEnabled(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
