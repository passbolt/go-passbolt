package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/speatzle/go-passbolt/api"
)

// AddMFACallbackTOTP adds a MFA callback to the client that generates OTP Codes on demand using a Token with configurable retries and delay
func AddMFACallbackTOTP(c *api.Client, retrys uint, retryDelay, offset time.Duration, token string) {
	c.MFACallback = func(ctx context.Context, c *api.Client, res *api.APIResponse) (http.Cookie, error) {
		challange := api.MFAChallange{}
		err := json.Unmarshal(res.Body, &challange)
		if err != nil {
			return http.Cookie{}, fmt.Errorf("Parsing MFA Challange")
		}
		if challange.Provider.TOTP == "" {
			return http.Cookie{}, fmt.Errorf("Server Provided no TOTP Provider")
		}
		for i := uint(0); i < retrys+1; i++ {
			var code string
			code, err = GenerateOTPCode(token, time.Now().Add(offset))
			if err != nil {
				return http.Cookie{}, fmt.Errorf("Error Generating MFA Code: %w", err)
			}
			req := api.MFAChallangeResponse{
				TOTP: code,
			}
			var raw *http.Response
			raw, _, err = c.DoCustomRequestAndReturnRawResponse(ctx, "POST", "mfa/verify/totp.json", "v2", req, nil)
			if err != nil {
				if errors.Unwrap(err) != api.ErrAPIResponseErrorStatusCode {
					return http.Cookie{}, fmt.Errorf("Doing MFA Challange Response: %w", err)
				}
				// MFA failed, so lets wait just let the loop try again
				time.Sleep(retryDelay)
			} else {
				// MFA worked so lets find the cookie and return it
				for _, cookie := range raw.Cookies() {
					if cookie.Name == "passbolt_mfa" {
						return *cookie, nil
					}
				}
				return http.Cookie{}, fmt.Errorf("Unable to find Passbolt MFA Cookie")
			}
		}
		return http.Cookie{}, fmt.Errorf("Failed MFA Challange 3 times: %w", err)
	}
}
