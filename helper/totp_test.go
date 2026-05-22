package helper

import (
	"testing"
	"time"
)

// rfc6238SharedKey is the base32 encoding of the ASCII secret
// "12345678901234567890" used throughout RFC 6238 Appendix B. The
// reference vectors below are the published test outputs for that
// secret with HMAC-SHA1 and a 30-second time step.
const rfc6238SharedKey = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// TestGenerateOTPCode_RFC6238Vectors locks down the TOTP algorithm
// against the published RFC 6238 Appendix B test vectors. The vectors
// are 8-digit codes; this implementation truncates to 6 digits, so we
// compare against the last 6 digits of each RFC vector.
//
// A regression in the HMAC counter, the offset extraction, or the
// modulo step would produce different codes — the existing test (using
// time.Now() and only checking length) would not have caught any of
// those.
func TestGenerateOTPCode_RFC6238Vectors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		unixTime int64
		want     string // last 6 digits of the RFC's 8-digit code
	}{
		// RFC 6238 Appendix B, SHA-1 column:
		//   59       -> 94287082 -> "287082"
		//   1111111109 -> 07081804 -> "081804"
		//   1111111111 -> 14050471 -> "050471"
		//   1234567890 -> 89005924 -> "005924"
		//   2000000000 -> 69279037 -> "279037"
		{"T=59", 59, "287082"},
		{"T=1111111109", 1111111109, "081804"},
		{"T=1111111111", 1111111111, "050471"},
		{"T=1234567890", 1234567890, "005924"},
		{"T=2000000000", 2000000000, "279037"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := GenerateOTPCode(rfc6238SharedKey, time.Unix(tc.unixTime, 0))
			if err != nil {
				t.Fatalf("GenerateOTPCode: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q (RFC 6238 vector for T=%d)", got, tc.want, tc.unixTime)
			}
		})
	}
}

// TestGenerateOTPCode_NormalizesInput verifies the documented input
// cleanup: the function trims spaces, uppercases the secret, and
// strips trailing `=` padding before base32-decoding. All four
// variants below MUST produce the same code as the canonical
// uppercase no-space form — otherwise users pasting a secret from
// an authenticator app (which may include spaces or padding) get
// different codes than the same secret typed cleanly.
func TestGenerateOTPCode_NormalizesInput(t *testing.T) {
	t.Parallel()

	const fixedTime = int64(1234567890)
	canonical, err := GenerateOTPCode(rfc6238SharedKey, time.Unix(fixedTime, 0))
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}

	variants := []struct {
		name  string
		input string
	}{
		{"lowercase", "gezdgnbvgy3tqojqgezdgnbvgy3tqojq"},
		{"with-spaces", "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ"},
		{"with-padding", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ===="},
		{"mixed-case-and-spaces", "gezd GNBV gy3t QOJQ gezd GNBV gy3t QOJQ"},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			got, err := GenerateOTPCode(v.input, time.Unix(fixedTime, 0))
			if err != nil {
				t.Fatalf("GenerateOTPCode(%q): %v", v.input, err)
			}
			if got != canonical {
				t.Errorf("got %q, want canonical %q (variant %q must normalize to the same code)", got, canonical, v.name)
			}
		})
	}
}

// TestGenerateOTPCode_RejectsInvalidBase32 ensures malformed input
// surfaces as an error rather than silently producing a code from
// partial bytes. The "1" character isn't in the base32 alphabet
// (which uses A-Z + 2-7), so this is genuinely invalid.
func TestGenerateOTPCode_RejectsInvalidBase32(t *testing.T) {
	t.Parallel()

	_, err := GenerateOTPCode("INVALIDTOKEN111", time.Unix(0, 0))
	if err == nil {
		t.Fatal("expected base32 decode error, got nil")
	}
}
