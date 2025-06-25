package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/google/go-querystring/query"
)

// Client is a Client struct for the Passbolt api
type Client struct {
	baseURL    *url.URL
	userAgent  string
	httpClient *http.Client

	sessionToken http.Cookie
	csrfToken    http.Cookie
	mfaToken     http.Cookie

	// userPublicKey has been removed since it can be gotten from the private userPrivateKey

	// be sure to make a copy since using ClearPrivateParams on a handler also wipes the key...
	userPrivateKey *crypto.Key
	userID         string

	// Server Settings Determining which Resource Types we can use
	metadataTypeSettings MetadataTypeSettings

	// Server Settings Determining which Metadata Keys to use
	metadataKeySettings MetadataKeySettings

	// Server Settings for password expiry
	passwordExpirySettings PasswordExpirySettings

	// used for solving MFA challenges. You can block this to for example wait for user input.
	// You shouden't run any unrelated API Calls while you are in this callback.
	// You need to Return the Cookie that Passbolt expects to verify you MFA, usually it is called passbolt_mfa
	MFACallback func(ctx context.Context, c *Client, res *APIResponse) (http.Cookie, error)

	// gopengpg Handler, allow for custom settings in the future
	pgp *crypto.PGPHandle

	// Enable Debug Logging
	Debug bool
}

// PublicKeyReponse the Body of a Public Key Api Request
type PublicKeyReponse struct {
	Fingerprint string `json:"fingerprint"`
	Keydata     string `json:"keydata"`
}

// NewClient Returns a new Passbolt Client.
// if httpClient is nil http.DefaultClient will be used.
// if UserAgent is "" "goPassboltClient/1.0" will be used.
// if UserPrivateKey is "" Key Setup is Skipped to Enable using the Client for User Registration, Most other function will be broken.
// After Registration a new Client Should be Created.
func NewClient(httpClient *http.Client, UserAgent, BaseURL, UserPrivateKey, UserPassword string) (*Client, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if UserAgent == "" {
		UserAgent = "goPassboltClient/1.0"
	}

	u, err := url.Parse(BaseURL)
	if err != nil {
		return nil, fmt.Errorf("Parsing Base URL: %w", err)
	}

	pgp := crypto.PGP()

	var unlockedKey *crypto.Key = nil
	if UserPrivateKey != "" {
		key, err := GetPrivateKeyFromArmor(UserPrivateKey, []byte(UserPassword))
		if err != nil {
			return nil, fmt.Errorf("Get Private Key: %w", err)
		}
		unlockedKey = key
	}

	// Create Client Object
	c := &Client{
		httpClient:     httpClient,
		baseURL:        u,
		userAgent:      UserAgent,
		userPrivateKey: unlockedKey,
		pgp:            pgp,
	}
	return c, err
}

func (c *Client) newRequest(method, url string, body interface{}) (*http.Request, error) {
	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, fmt.Errorf("JSON Encoding Request: %w", err)
		}
	}

	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		return nil, fmt.Errorf("Creating HTTP Request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("X-CSRF-Token", c.csrfToken.Value)
	req.AddCookie(&c.sessionToken)
	req.AddCookie(&c.csrfToken)
	if c.mfaToken.Name != "" {
		req.AddCookie(&c.mfaToken)
	}

	// Debugging
	c.log("Request URL: %v", req.URL.String())
	if c.Debug && body != nil {
		data, err := json.Marshal(body)
		if err == nil {
			c.log("Raw Request: %v", string(data))
		}
	}

	return req, nil
}

func (c *Client) do(ctx context.Context, req *http.Request, v *APIResponse) (*http.Response, error) {
	req = req.WithContext(ctx)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("Request Context: %w", ctx.Err())
		default:
			return nil, fmt.Errorf("Request: %w", err)
		}
	}
	defer func() {
		resp.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, fmt.Errorf("Error Reading Resopnse Body: %w", err)
	}

	c.log("Raw Response: %v", string(bodyBytes))

	err = json.Unmarshal(bodyBytes, v)
	if err != nil {
		return resp, fmt.Errorf("Unable to Parse JSON API Response with HTTP Status Code %v: %w", resp.StatusCode, err)
	}

	return resp, nil
}

func (c *Client) log(msg string, args ...interface{}) {
	if !c.Debug {
		return
	}
	fmt.Printf("[go-passbolt] "+msg+"\n", args...)
}

func generateURL(base url.URL, p string, opt interface{}) (string, error) {
	base.Path = path.Join(base.Path, p)
	vs, err := query.Values(opt)
	if err != nil {
		return "", fmt.Errorf("Getting URL Query Values: %w", err)
	}
	base.RawQuery = vs.Encode()

	return base.String(), nil
}

// GetUserID Gets the ID of the Current User
func (c *Client) GetUserID() string {
	return c.userID
}

// GetPublicKey gets the Public Key and Fingerprint of the Passbolt instance
func (c *Client) GetPublicKey(ctx context.Context) (string, string, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/auth/verify.json", "v2", nil, nil)
	if err != nil {
		return "", "", fmt.Errorf("Doing Request: %w", err)
	}

	var body PublicKeyReponse
	err = json.Unmarshal(msg.Body, &body)
	if err != nil {
		return "", "", fmt.Errorf("Parsing JSON: %w", err)
	}

	// Lets get the actual Fingerprint instead of trusting the Server
	serverKey, err := crypto.NewKeyFromArmored(body.Keydata)
	if err != nil {
		return "", "", fmt.Errorf("Parsing Server Key: %w", err)
	}
	return body.Keydata, serverKey.GetFingerprint(), nil
}

// setMetadataTypeSettings Gets and configures the Client to use the Types the Server wants us to use
func (c *Client) setMetadataTypeSettings(ctx context.Context, settings *ServerSettingsResponse) error {
	if settings.Passbolt.IsPluginEnabled("metadata") {
		c.log("Server has metadata plugin enabled, is v5 or Higher")
		metadataTypeSettings, err := c.GetServerMetadataTypeSettings(ctx)
		if err != nil {
			return fmt.Errorf("Getting Metadata Type Settings: %w", err)
		}

		c.log("metadataTypeSettings: %+v", metadataTypeSettings)
		c.metadataTypeSettings = *metadataTypeSettings

		metadataKeySettings, err := c.GetServerMetadataKeySettings(ctx)
		if err != nil {
			return fmt.Errorf("Getting Metadata Key Settings: %w", err)
		}

		c.log("metadataKeySettings: %+v", metadataKeySettings)
		c.metadataKeySettings = *metadataKeySettings
	} else {
		c.log("Server has metadata plugin disabled or not installed, Server is v4")
		c.metadataTypeSettings = getV4DefaultMetadataTypeSettings()
		c.metadataKeySettings = MetadataKeySettings{
			AllowUsageOfPersonalKeys:   true,
			AllowZeroKnowledgeKeyShare: false,
		}
	}
	return nil
}

// setPasswordExpirySettings fetches and configures the Client to use the password expiry plugin
func (c *Client) setPasswordExpirySettings(ctx context.Context, settings *ServerSettingsResponse) error {
	if settings.Passbolt.IsPluginEnabled("passwordExpiry") && settings.Passbolt.IsPluginEnabled("passwordExpiryPolicies") {
		c.log("Server has password expiry plugin enabled.")
		passwordExpirySettings, err := c.getServerPasswordExpirySettings(ctx)
		if err != nil {
			return fmt.Errorf("Getting Password Expiry Settings: %w", err)
		}

		c.log("passwordExpirySettings: %+v", passwordExpirySettings)
		c.passwordExpirySettings = *passwordExpirySettings
	} else {
		c.log("Server has password expiry plugin disabled or not installed.")
		c.passwordExpirySettings = getDefaultPasswordExpirySettings()
	}

	return nil
}

// GetPGPHandle Gets the Gopgenpgp Handler
func (c *Client) GetPGPHandle() *crypto.PGPHandle {
	return c.pgp
}

// GetPasswordExpirySettings returns the password expiry settings for the client
func (c *Client) GetPasswordExpirySettings() PasswordExpirySettings {
	return c.passwordExpirySettings
}
