package helper

import (
	"testing"
	"time"
)

// FuzzGenerateOTPCode fuzzes the base32 secret and the time counter. The hot
// path decodes the (normalized) base32 token and then indexes into the HMAC-SHA1
// digest with a value derived from its last byte, so a malformed or short secret
// is the obvious panic risk. Invariant: it either returns an error, or returns a
// string of exactly codeLength ASCII digits — never a partial/garbage code.
func FuzzGenerateOTPCode(f *testing.F) {
	f.Add("JBSWY3DPEHPK3PXP", int64(0))
	f.Add("JBSW Y3DP EHPK 3PXP", int64(59))
	f.Add("jbswy3dpehpk3pxp==", int64(1234567890))
	f.Add("", int64(0))
	f.Add("not-base32!!!", int64(-1))

	f.Fuzz(func(t *testing.T, token string, unix int64) {
		code, err := GenerateOTPCode(token, time.Unix(unix, 0))
		if err != nil {
			return
		}
		if len(code) != codeLength {
			t.Fatalf("GenerateOTPCode returned %d-char code %q, want %d digits", len(code), code, codeLength)
		}
		for i, r := range code {
			if r < '0' || r > '9' {
				t.Fatalf("non-digit %q at index %d in code %q (token %q)", r, i, code, token)
			}
		}
	})
}
