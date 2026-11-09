package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// BrowserGrant is a single-use authorization bound to a SHA-256 verifier challenge.
// It must be obtained through a trusted browser extension, never from command arguments.
type BrowserGrant struct {
	Token    string `json:"token"`
	UserID   string `json:"user_id"`
	Verifier string `json:"verifier"`
}

// LoginWithBrowserGrant creates an independent session using a browser-approved
// grant. The client must already hold the account's unlocked private key.
// Callers must serialize this with all other operations on the client.
func (c *Client) LoginWithBrowserGrant(ctx context.Context, grant BrowserGrant) (err error) {
	if c.Debug {
		return fmt.Errorf("debug logging is unavailable during browser authorization")
	}
	if grant.Token == "" || grant.UserID == "" || len(grant.Verifier) != 43 {
		return fmt.Errorf("incomplete browser authorization grant")
	}
	c.cryptoMu.RLock()
	hasKey := c.userPrivateKey != nil
	c.cryptoMu.RUnlock()
	if !hasKey {
		return ErrNoPrivateKey
	}
	if c.sessionToken.Value != "" {
		return fmt.Errorf("client already has a session")
	}
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if c.sessionToken.Value != "" {
				_ = c.Logout(cleanup)
			}
			c.Close()
		}
	}()
	raw, res, err := c.DoCustomRequestAndReturnRawResponse(ctx, "POST", "/browser-auth/exchange.json", "v2", grant, nil)
	if err != nil {
		return fmt.Errorf("exchanging browser authorization: %w", err)
	}
	for _, cookie := range raw.Cookies() {
		switch cookie.Name {
		case "passbolt_session", "CAKEPHP", "PHPSESSID":
			c.sessionToken = *cookie
		case "passbolt_mfa":
			c.mfaToken = *cookie
		}
	}
	if c.sessionToken.Value == "" {
		return ErrSessionNotFound
	}
	var result struct {
		UserID string `json:"user_id"`
	}
	if err = json.Unmarshal(res.Body, &result); err != nil || result.UserID != grant.UserID {
		return fmt.Errorf("browser authorization returned a different account")
	}
	return c.initializeAuthenticatedSession(ctx, grant.UserID)
}

// Close clears local keys, cached plaintext and session credentials without a
// network request. Use Logout first when remote session revocation is desired.
func (c *Client) Close() {
	c.sessionToken = http.Cookie{}
	c.csrfToken = http.Cookie{}
	c.mfaToken = http.Cookie{}
	c.ClearCache()
	c.cryptoMu.Lock()
	defer c.cryptoMu.Unlock()
	if c.userPrivateKey != nil {
		c.userPrivateKey.ClearPrivateParams()
		c.userPrivateKey = nil
	}
}
