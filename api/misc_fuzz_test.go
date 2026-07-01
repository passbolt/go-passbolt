package api

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// FuzzCheckAuthTokenFormat exercises the GPGAuth challenge-token validator with
// arbitrary "|"-delimited input. The function does index access, a strconv.Atoi,
// and a length comparison on user-influenced data, so the property we assert is:
// it never panics, and any token it accepts genuinely satisfies every structural
// rule it claims to enforce.
func FuzzCheckAuthTokenFormat(f *testing.F) {
	f.Add("gpgauthv1.3.0|36|11111111-2222-3333-4444-555555555555|gpgauthv1.3.0")
	f.Add("gpgauthv1.3.0|36|abc")
	f.Add("gpgauthv1.3.0|notnum|abc|gpgauthv1.3.0")
	f.Add("gpgauthv1.3.0|99|short|gpgauthv1.3.0")
	f.Add("other|36|abc|other")
	f.Add("")
	f.Add("|||")

	f.Fuzz(func(t *testing.T, token string) {
		err := checkAuthTokenFormat(token)
		if err != nil {
			return
		}
		// Accepted: re-verify every invariant the validator promises.
		parts := strings.Split(token, "|")
		if len(parts) != 4 {
			t.Fatalf("accepted token with %d fields: %q", len(parts), token)
		}
		if parts[0] != parts[3] {
			t.Fatalf("accepted token with mismatched version fields: %q", token)
		}
		if !strings.HasPrefix(parts[0], "gpgauth") {
			t.Fatalf("accepted token without gpgauth prefix: %q", token)
		}
		length, convErr := strconv.Atoi(parts[1])
		if convErr != nil {
			t.Fatalf("accepted token with non-numeric length field: %q", token)
		}
		if len(parts[2]) != length {
			t.Fatalf("accepted token with data length %d != length field %d: %q", len(parts[2]), length, token)
		}
	})
}

// FuzzCheckUUIDFormat throws arbitrary strings (long, Unicode, regex-special) at
// the UUID gate. Invariant: it returns either nil or ErrInvalidUUID and never any
// other error or panic, and anything it accepts is exactly 36 bytes long (the
// canonical 8-4-4-4-12 form the regex pins down).
func FuzzCheckUUIDFormat(f *testing.F) {
	f.Add(validUUID)
	f.Add("")
	f.Add("abc")
	f.Add("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz")
	f.Add("AaBbCcDd-1234-5678-9ABC-DEF012345678")

	f.Fuzz(func(t *testing.T, in string) {
		err := checkUUIDFormat(in)
		if err == nil {
			if len(in) != 36 {
				t.Fatalf("accepted non-canonical-length UUID (%d bytes): %q", len(in), in)
			}
			return
		}
		if !errors.Is(err, ErrInvalidUUID) {
			t.Fatalf("got unexpected error %v for %q, want nil or ErrInvalidUUID", err, in)
		}
	})
}
