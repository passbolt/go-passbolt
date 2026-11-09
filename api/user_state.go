package api

import (
	"context"
	"fmt"
	"time"
)

// DisableUser disables an account without deleting it. Passbolt requires a UTC
// CakePHP datetime for this update rather than the RFC3339 response format.
func (c *Client) DisableUser(ctx context.Context, userID string) error {
	return c.setUserDisabled(ctx, userID, time.Now().UTC().Format("2006-01-02 15:04:05"))
}

// EnableUser enables a disabled account. The request must contain an explicit
// JSON null; a nil User.Disabled would be omitted by UpdateUser.
func (c *Client) EnableUser(ctx context.Context, userID string) error {
	return c.setUserDisabled(ctx, userID, nil)
}

func (c *Client) setUserDisabled(ctx context.Context, userID string, disabled any) error {
	if err := checkUUIDFormat(userID); err != nil {
		return fmt.Errorf("checking ID format: %w", err)
	}
	_, err := c.DoCustomRequest(ctx, "PUT", "/users/"+userID+".json", "v2", struct {
		Disabled any `json:"disabled"`
	}{Disabled: disabled}, nil)
	return err
}
