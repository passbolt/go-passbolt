package server

import "testing"

// An ignored override would report results under the wrong Passbolt version.
func TestPassboltImage(t *testing.T) {
	t.Run("defaults to the pinned image", func(t *testing.T) {
		t.Setenv(PassboltImageEnv, "")
		if got := PassboltImage(); got != defaultPassboltImage {
			t.Errorf("PassboltImage() = %q, want the pinned default %q", got, defaultPassboltImage)
		}
	})

	t.Run("honors the override", func(t *testing.T) {
		const want = "passbolt/passbolt:5.14.0-1-ce"
		t.Setenv(PassboltImageEnv, want)
		if got := PassboltImage(); got != want {
			t.Errorf("PassboltImage() = %q, want %q", got, want)
		}
	})

	t.Run("treats a blank override as unset", func(t *testing.T) {
		// Callers may export the variable empty rather than unset it.
		t.Setenv(PassboltImageEnv, "   \t ")
		if got := PassboltImage(); got != defaultPassboltImage {
			t.Errorf("PassboltImage() = %q, want the pinned default %q", got, defaultPassboltImage)
		}
	})

	t.Run("trims surrounding whitespace", func(t *testing.T) {
		t.Setenv(PassboltImageEnv, "  passbolt/passbolt:5.0.0-1-ce\n")
		if got, want := PassboltImage(), "passbolt/passbolt:5.0.0-1-ce"; got != want {
			t.Errorf("PassboltImage() = %q, want %q", got, want)
		}
	})
}
