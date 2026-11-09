package api

import (
	"context"
	"fmt"
	"strings"
)

// RecoverUser requests an account recovery email, or renews the invitation for
// an account that has not completed setup. The server controls email delivery
// and may return success without disclosing whether the account exists.
func (c *Client) RecoverUser(ctx context.Context, username string) error {
	if strings.TrimSpace(username) == "" {
		return fmt.Errorf("username must not be empty")
	}
	_, err := c.DoCustomRequest(ctx, "POST", "/users/recover.json", "v2", struct {
		Username string `json:"username"`
	}{Username: username}, nil)
	return err
}
