package helper

import (
	"testing"
	"time"
)

var testCases = []struct {
	description string
	token       string
	expectErr   bool
}{
	{"generates otpcode from token with padding", "PGWXXL7B66MMSRBAWSKEKIYD3P675KRJ===", false},
	{"generates otpcode from token without padding", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", false},
	{"invalid token format", "INVALIDTOKEN123", true},
}

func TestGenerateOTPCode(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			code, err := GenerateOTPCode(tc.token, time.Now())

			if tc.expectErr {
				if err == nil {
					t.Errorf("Expected error for input '%s', but got none", tc.token)
				}
			} else {
				if err != nil {
					t.Errorf("GenerateOTPCode returned an error: %s", err.Error())
				} else if len(code) != 6 {
					t.Errorf("Expected 6-digit OTP, got: %s", code)
				}
			}
		})
	}
}
