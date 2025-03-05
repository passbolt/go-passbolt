package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

// Login is used for login
type Login struct {
	Auth *GPGAuth `json:"gpg_auth"`
}

// GPGAuth is used for login
type GPGAuth struct {
	KeyID string `json:"keyid"`
	Token string `json:"user_token_result,omitempty"`
}

// CheckSession Check to see if you have a Valid Session
func (c *Client) CheckSession(ctx context.Context) bool {
	_, err := c.DoCustomRequest(ctx, "GET", "auth/is-authenticated.json", nil, nil)
	return err == nil
}

// Login gets a Session and CSRF Token from Passbolt and Stores them in the Clients Cookie Jar
func (c *Client) Login(ctx context.Context) error {
	c.csrfToken = http.Cookie{}

	if c.userPrivateKey == "" {
		return fmt.Errorf("Client has no Private Key")
	}

	privateKeyObj, err := crypto.NewKeyFromArmored(c.userPrivateKey)
	if err != nil {
		return fmt.Errorf("Parsing User Private Key: %w", err)
	}
	data := Login{&GPGAuth{KeyID: privateKeyObj.GetFingerprint()}}

	res, _, err := c.DoCustomRequestAndReturnRawResponseV5(ctx, "POST", "/auth/login.json", data, nil)
	if err != nil && !strings.Contains(err.Error(), "Error API JSON Response Status: Message: The authentication failed.") {
		return fmt.Errorf("Doing Stage 1 Request: %w", err)
	}

	encAuthToken := res.Header.Get("X-GPGAuth-User-Auth-Token")

	if encAuthToken == "" {
		return fmt.Errorf("Got Empty X-GPGAuth-User-Auth-Token Header")
	}

	c.log("Got Encrypted Auth Token: %v", encAuthToken)

	encAuthToken, err = url.QueryUnescape(encAuthToken)
	if err != nil {
		return fmt.Errorf("Unescaping User Auth Token: %w", err)
	}
	encAuthToken = strings.ReplaceAll(encAuthToken, "\\ ", " ")

	authToken, err := helper.DecryptMessageArmored(c.userPrivateKey, c.userPassword, encAuthToken)
	if err != nil {
		return fmt.Errorf("Decrypting User Auth Token: %w", err)
	}

	c.log("Decrypted Auth Token: %v", authToken)

	err = checkAuthTokenFormat(authToken)
	if err != nil {
		return fmt.Errorf("Checking Auth Token Format: %w", err)
	}

	data.Auth.Token = string(authToken)

	res, _, err = c.DoCustomRequestAndReturnRawResponseV5(ctx, "POST", "/auth/login.json", data, nil)
	if err != nil {
		return fmt.Errorf("Doing Stage 2 Request: %w", err)
	}

	c.log("Got Cookies: %+v", res.Cookies())

	for _, cookie := range res.Cookies() {
		if cookie.Name == "passbolt_session" {
			c.sessionToken = *cookie
			// Session Cookie in older Passbolt Versions
		} else if cookie.Name == "CAKEPHP" {
			c.sessionToken = *cookie
			// Session Cookie in Cloud version?
		} else if cookie.Name == "PHPSESSID" {
			c.sessionToken = *cookie
		}
	}
	if c.sessionToken.Name == "" {
		return fmt.Errorf("Cannot Find Session Cookie!")
	}

	// Because of MFA, the custom Request Function now Fetches the CSRF token, we still need the user for his public key
	apiMsg, err := c.DoCustomRequest(ctx, "GET", "/users/me.json", nil, nil)
	if err != nil {
		return fmt.Errorf("Getting CSRF Token: %w", err)
	}

	// Get Users Own Public Key from Server
	var user User
	err = json.Unmarshal(apiMsg.Body, &user)
	if err != nil {
		return fmt.Errorf("Parsing User 'Me' JSON from API Request: %w", err)
	}

	// Validate that this Publickey that the Server gave us actually Matches our Privatekey
	randomString := randStringBytesRmndr(50)
	armor, err := helper.EncryptMessageArmored(user.GPGKey.ArmoredKey, randomString)
	if err != nil {
		return fmt.Errorf("Encryping PublicKey Validation Message: %w", err)
	}
	decrypted, err := helper.DecryptMessageArmored(c.userPrivateKey, c.userPassword, armor)
	if err != nil {
		return fmt.Errorf("Decrypting PublicKey Validation Message (you might be getting Hacked): %w", err)
	}
	if decrypted != randomString {
		return fmt.Errorf("Decrypted PublicKey Validation Message does not Match Original (you might be getting Hacked): %w", err)
	}

	// Insert PublicKey into Client after checking it to Prevent ignored errors leading to proceeding with a potentially Malicious PublicKey
	c.userPublicKey = user.GPGKey.ArmoredKey
	c.userID = user.ID

	return nil
}

// Logout closes the current Session on the Passbolt server
func (c *Client) Logout(ctx context.Context) error {
	_, err := c.DoCustomRequest(ctx, "GET", "/auth/logout.json", nil, nil)
	if err != nil {
		return fmt.Errorf("Doing Logout Request: %w", err)
	}
	c.sessionToken = http.Cookie{}
	c.csrfToken = http.Cookie{}
	return nil
}
