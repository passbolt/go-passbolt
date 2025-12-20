package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	_, err := c.DoCustomRequest(ctx, "GET", "auth/is-authenticated.json", "v2", nil, nil)
	return err == nil
}

// Login gets a Session and CSRF Token from Passbolt and Stores them in the Clients Cookie Jar
func (c *Client) Login(ctx context.Context) error {
	// Validate client has private key (not logged out)
	if c.userPrivateKey == nil {
		return fmt.Errorf("Cannot login: client has no user private key (logged out or not initialized)")
	}

	// Clear any cached data from previous sessions
	c.ClearCache()
	c.csrfToken = http.Cookie{}

	data := Login{&GPGAuth{KeyID: c.userPrivateKey.GetFingerprint()}}

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

	authToken, err := c.DecryptMessage(encAuthToken)
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
			// Session Cookie in Cloud version?
		} else if cookie.Name == "PHPSESSID" {
			c.sessionToken = *cookie
		}
	}
	if c.sessionToken.Name == "" {
		return fmt.Errorf("Cannot Find Session Cookie!")
	}

	// Because of MFA, the custom Request Function now Fetches the CSRF token, we still need the user for his public key
	apiMsg, err := c.DoCustomRequest(ctx, "GET", "/users/me.json", "v2", nil, nil)
	if err != nil {
		return fmt.Errorf("Getting CSRF Token: %w", err)
	}

	// Get Users ID from Server
	var user User
	err = json.Unmarshal(apiMsg.Body, &user)
	if err != nil {
		return fmt.Errorf("Parsing User 'Me' JSON from API Request: %w", err)
	}

	c.userID = user.ID

	settings, err := c.GetServerSettings(ctx)
	if err != nil {
		return fmt.Errorf("Getting Server Settings: %w", err)
	}

	// after Login, fetch MetadataTypeSettings to finish the Client Setup
	err = c.setMetadataTypeSettings(ctx, settings)
	if err != nil {
		return fmt.Errorf("Setup Metadata Type Settings: %w", err)
	}

	err = c.setPasswordExpirySettings(ctx, settings)
	if err != nil {
		return fmt.Errorf("Setup Password Expiry Settings: %w", err)
	}

	// Pre-fetch caches if server supports v5 metadata encryption
	if c.metadataTypeSettings.AllowCreationOfV5Resources {
		sessionCount, metadataCount, err := c.PreFetchCaches(ctx)
		if err != nil {
			// Log but don't fail login - this is an optional optimization
			c.log("Warning: Failed to pre-fetch caches: %v", err)
		} else {
			c.log("Pre-fetched %d session keys and %d metadata keys", sessionCount, metadataCount)
		}
	}

	return nil
}

// Logout closes the current Session on the Passbolt server
// IMPORTANT: After logout, the client's user private key is securely zeroed and cleared.
// The client becomes permanently invalid and CANNOT be reused or re-logged in.
// For a new session, create a new client instance with NewClient().
func (c *Client) Logout(ctx context.Context) error {
	_, err := c.DoCustomRequest(ctx, "GET", "/auth/logout.json", "v2", nil, nil)
	if err != nil {
		return fmt.Errorf("Doing Logout Request: %w", err)
	}

	// Clear session cookies
	c.sessionToken = http.Cookie{}
	c.csrfToken = http.Cookie{}

	// Clear all caches with secure zeroing
	c.ClearCache()

	// Securely clear user private key
	if c.userPrivateKey != nil {
		c.userPrivateKey.ClearPrivateParams()
		c.userPrivateKey = nil
	}

	return nil
}
