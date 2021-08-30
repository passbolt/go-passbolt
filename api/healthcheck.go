package api

import (
	"context"
	"encoding/json"
)

// PerformHealthCheck performs a Health Check
func (c *Client) PerformHealthCheck(ctx context.Context) (json.RawMessage, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/healthcheck.json", "v2", nil, nil)
	if err != nil {
		return nil, err
	}

	return msg.Body, nil
}

// GetHealthCheckStatus gets the Server Status
func (c *Client) GetHealthCheckStatus(ctx context.Context) (string, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/healthcheck/status.json", "v2", nil, nil)
	if err != nil {
		return "", err
	}

	return string(msg.Body), nil
}
