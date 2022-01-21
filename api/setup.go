package api

import (
	"context"
	"encoding/json"
	"fmt"
)

type SetupInstallResponse struct {
	User `json:"user,omitempty"`
}

type AuthenticationToken struct {
	Token string `json:"token,omitempty"`
}

type SetupCompleteRequest struct {
	AuthenticationToken AuthenticationToken `json:"authenticationtoken,omitempty"`
	GPGKey              GPGKey              `json:"gpgkey,omitempty"`
	User                User                `json:"user,omitempty"`
}

// SetupInstall validates the userid and token used for Account setup, gives back the User Information
func (c *Client) SetupInstall(ctx context.Context, userID, token string) (*SetupInstallResponse, error) {
	err := checkUUIDFormat(userID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	err = checkUUIDFormat(token)
	if err != nil {
		return nil, fmt.Errorf("Checking Token format: %w", err)
	}
	msg, err := c.DoCustomRequest(ctx, "GET", "/setup/install/"+userID+"/"+token+".json", "v2", nil, nil)
	if err != nil {
		return nil, err
	}

	var install SetupInstallResponse
	err = json.Unmarshal(msg.Body, &install)
	if err != nil {
		return nil, err
	}
	return &install, nil
}

// SetupComplete Completes setup of a Passbolt Account
func (c *Client) SetupComplete(ctx context.Context, userID string, request SetupCompleteRequest) error {
	err := checkUUIDFormat(userID)
	if err != nil {
		return fmt.Errorf("Checking ID format: %w", err)
	}
	_, err = c.DoCustomRequest(ctx, "POST", "/setup/complete/"+userID+".json", "v2", request, nil)
	if err != nil {
		return err
	}
	return nil
}
