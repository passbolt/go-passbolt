package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

// PublicKeyReponse the Body of a Public Key Api Request
type PublicKeyReponse struct {
	Fingerprint string `json:"fingerprint"`
	Keydata     string `json:"keydata"`
}

// Login is used for login
type Login struct {
	Auth *GPGAuth `json:"gpg_auth"`
}

// GPGAuth is used for login
type GPGAuth struct {
	KeyID string `json:"keyid"`
	Token string `json:"user_token_result,omitempty"`
}

// TODO add Server Verification Function

// GetPublicKey gets the Public Key and Fingerprint of the Passbolt instance
func (c *Client) GetPublicKey(ctx context.Context) (string, string, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "auth/verify.json", "v2", nil, nil)
	if err != nil {
		return "", "", fmt.Errorf("Doing Request: %w", err)
	}

	var body PublicKeyReponse
	err = json.Unmarshal(msg.Body, &body)
	if err != nil {
		return "", "", fmt.Errorf("Parsing JSON: %w", err)
	}
	// TODO check if that Fingerpirnt is actually from the Publickey
	return body.Keydata, body.Fingerprint, nil
}

// CheckSession Check to see if you have a Valid Session
func (c *Client) CheckSession(ctx context.Context) bool {
	_, err := c.DoCustomRequest(ctx, "GET", "auth/is-authenticated.json", "v2", nil, nil)
	return err == nil
}

// Login gets a Session and CSRF Token from Passbolt and Stores them in the Clients Cookie Jar
func (c *Client) Login(ctx context.Context) error {

	if c.userPrivateKey == "" {
		return fmt.Errorf("Client has no Private Key")
	}

	privateKeyObj, err := crypto.NewKeyFromArmored(c.userPrivateKey)
	if err != nil {
		return fmt.Errorf("Parsing User Private Key: %w", err)
	}
	data := Login{&GPGAuth{KeyID: privateKeyObj.GetFingerprint()}}

	res, _, err := c.DoCustomRequestAndReturnRawResponse(ctx, "POST", "/auth/login.json", "v2", data, nil)
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

	res, _, err = c.DoCustomRequestAndReturnRawResponse(ctx, "POST", "/auth/login.json", "v2", data, nil)
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
		}
	}
	if c.sessionToken.Name == "" {
		return fmt.Errorf("Cannot Find Session Cookie!")
	}

	// Do Mfa Here if ever

	// You have to get a make GET Request to get the CSRF Token which is Required for Write Operations
	msg, apiMsg, err := c.DoCustomRequestAndReturnRawResponse(ctx, "GET", "/users/me.json", "v2", nil, nil)
	if err != nil {
		c.log("is MFA Enabled? That is not yet Supported!")
		return fmt.Errorf("Getting CSRF Token: %w", err)
	}

	for _, cookie := range msg.Cookies() {
		if cookie.Name == "csrfToken" {
			c.csrfToken = *cookie
		}
	}

	if c.csrfToken.Name == "" {
		return fmt.Errorf("Cannot Find csrfToken Cookie!")
	}

	// Get Users Own Public Key from Server
	var user User
	err = json.Unmarshal(apiMsg.Body, &user)
	if err != nil {
		return fmt.Errorf("Parsing User 'Me' JSON from API Request: %w", err)
	}

	// Validate that this Publickey that the Server gave us actually Matches our Privatekey
	randomString, err := randStringBytesRmndr(50)
	if err != nil {
		return fmt.Errorf("Generating Random String as PublicKey Validation Message: %w", err)
	}
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
	_, err := c.DoCustomRequest(ctx, "GET", "/auth/logout.json", "v2", nil, nil)
	if err != nil {
		return fmt.Errorf("Doing Logout Request: %w", err)
	}
	c.sessionToken = http.Cookie{}
	c.csrfToken = http.Cookie{}
	return nil
}

// GetUserID Gets the ID of the Current User
func (c *Client) GetUserID() string {
	return c.userID
}

func checkAuthTokenFormat(authToken string) error {
	splitAuthToken := strings.Split(authToken, "|")
	if len(splitAuthToken) != 4 {
		return fmt.Errorf("Auth Token Has Wrong amount of Fields")
	}

	if splitAuthToken[0] != splitAuthToken[3] {
		return fmt.Errorf("Auth Token Version Fields Don't match")
	}

	if !strings.HasPrefix(splitAuthToken[0], "gpgauth") {
		return fmt.Errorf("Auth Token Version does not start with 'gpgauth'")
	}

	length, err := strconv.Atoi(splitAuthToken[1])
	if err != nil {
		return fmt.Errorf("Cannot Convert Auth Token Length Field to int: %w", err)
	}

	if len(splitAuthToken[2]) != length {
		return fmt.Errorf("Auth Token Data Length does not Match Length Field")
	}
	return nil
}
