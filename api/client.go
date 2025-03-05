package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
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

	// for some reason []byte is used for Passwords in gopenpgp instead of string like they do for keys...
	userPassword   []byte
	userPrivateKey string
	userPublicKey  string
	userID         string

	// used for solving MFA challenges. You can block this to for example wait for user input.
	// You shouden't run any unrelated API Calls while you are in this callback.
	// You need to Return the Cookie that Passbolt expects to verify you MFA, usually it is called passbolt_mfa
	MFACallback func(ctx context.Context, c *Client, res *APIResponse) (http.Cookie, error)

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

	// Verify that the Given Privatekey and Password are valid and work Together if we were provieded one
	if UserPrivateKey != "" {
		privateKeyObj, err := crypto.NewKeyFromArmored(UserPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("Unable to Create Key From UserPrivateKey string: %w", err)
		}
		unlockedKeyObj, err := privateKeyObj.Unlock([]byte(UserPassword))
		if err != nil {
			return nil, fmt.Errorf("Unable to Unlock UserPrivateKey using UserPassword: %w", err)
		}
		privateKeyRing, err := crypto.NewKeyRing(unlockedKeyObj)
		if err != nil {
			return nil, fmt.Errorf("Unable to Create a new Key Ring using the unlocked UserPrivateKey: %w", err)
		}

		// Cleanup Secrets
		privateKeyRing.ClearPrivateParams()
	}

	// Create Client Object
	c := &Client{
		httpClient:     httpClient,
		baseURL:        u,
		userAgent:      UserAgent,
		userPassword:   []byte(UserPassword),
		userPrivateKey: UserPrivateKey,
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

	bodyBytes, err := ioutil.ReadAll(resp.Body)
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
	privateKeyObj, err := crypto.NewKeyFromArmored(c.userPrivateKey)
	if err != nil {
		return "", "", fmt.Errorf("Parsing Server Key: %w", err)
	}
	return body.Keydata, privateKeyObj.GetFingerprint(), nil
}
