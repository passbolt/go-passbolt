package api

import (
	"errors"
	"strings"
	"testing"
)

// Misc-level tests cover the small but security-critical validators
// every entity method passes through before any HTTP call:
//   - checkUUIDFormat: client-side input validation
//   - checkAuthTokenFormat: post-decryption sanity check during Login

// TestCheckUUIDFormat exercises the regex used to gate per-id methods.
// "mixed case ok" is the most surprising case: real Passbolt UUIDs are
// lowercase, but the regex must accept any hex digit to keep
// compatibility with case-insensitive UUID generators.
func TestCheckUUIDFormat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"valid", validUUID, false},
		{"empty", "", true},
		{"too short", "abc", true},
		{"not hex", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", true},
		{"mixed case ok", "AaBbCcDd-1234-5678-9ABC-DEF012345678", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkUUIDFormat(tc.in)
			if tc.wantErr && !errors.Is(err, ErrInvalidUUID) {
				t.Errorf("got %v, want ErrInvalidUUID", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestCheckAuthTokenFormat is the protocol-level validator for the
// decrypted GPGAuth challenge token. Each failure mode triggers a
// distinct error message; we test each because Login uses the
// specific message to determine where in the four-leg auth flow
// something went wrong.
func TestCheckAuthTokenFormat(t *testing.T) {
	t.Parallel()

	valid := "gpgauthv1.3.0|36|11111111-2222-3333-4444-555555555555|gpgauthv1.3.0"
	if err := checkAuthTokenFormat(valid); err != nil {
		t.Errorf("expected valid token to pass, got %v", err)
	}

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"wrong field count", "gpgauthv1.3.0|36|abc", "amount of Fields"},
		{"version mismatch", "gpgauthv1.3.0|36|abc|gpgauthv9.9.9", "Version Fields"},
		{"missing gpgauth prefix", "other|36|abc|other", "gpgauth"},
		{"non-numeric length", "gpgauthv1.3.0|notnum|abc|gpgauthv1.3.0", "Length Field"},
		{"length mismatch", "gpgauthv1.3.0|99|short|gpgauthv1.3.0", "Length does not Match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkAuthTokenFormat(tc.in)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %q should contain %q", err.Error(), tc.want)
			}
		})
	}
}
