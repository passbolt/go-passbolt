package api

import (
	"context"
	"encoding/json"
	"fmt"
)

// ResourceShareRequest is a ResourceShareRequest
type ResourceShareRequest struct {
	Permissions []Permission `json:"permissions,omitempty"`
	Secrets     []Secret     `json:"secrets,omitempty"`
}

// ResourceShareSimulationResult is the Result of a Sharing Simulation
type ResourceShareSimulationResult struct {
	Changes ResourceShareSimulationChanges `json:"changes,omitempty"`
}

// ResourceShareSimulationChanges contains the Actual Changes
type ResourceShareSimulationChanges struct {
	Added   []ResourceShareSimulationChange `json:"added,omitempty"`
	Removed []ResourceShareSimulationChange `json:"removed,omitempty"`
}

// ResourceShareSimulationChange is a single change
type ResourceShareSimulationChange struct {
	User ResourceShareSimulationUser `json:"user,omitempty"`
}

// ResourceShareSimulationUser contains the users id
type ResourceShareSimulationUser struct {
	ID string `json:"id,omitempty"`
}

// ARO is a User or a Group
type ARO struct {
	User
	Group
}

// SearchAROsOptions are all available query parameters
type SearchAROsOptions struct {
	FilterSearch string `url:"filter[search],omitempty"`
}

// SearchAROs gets all Passbolt AROs
func (c *Client) SearchAROs(ctx context.Context, opts SearchAROsOptions) ([]ARO, error) {
	//set is_new to true in permission
	msg, err := c.DoCustomRequestV5(ctx, "GET", "/share/search-aros.json", nil, opts)
	if err != nil {
		return nil, err
	}

	var aros []ARO
	err = json.Unmarshal(msg.Body, &aros)
	if err != nil {
		return nil, err
	}
	return aros, nil
}

// ShareResource Shares a Resource with AROs
func (c *Client) ShareResource(ctx context.Context, resourceID string, shareRequest ResourceShareRequest) error {
	err := checkUUIDFormat(resourceID)
	if err != nil {
		return fmt.Errorf("Checking ID format: %w", err)
	}
	_, err = c.DoCustomRequestV5(ctx, "PUT", "/share/resource/"+resourceID+".json", shareRequest, nil)
	if err != nil {
		return err
	}

	return nil
}

// ShareFolder Shares a Folder with AROs
func (c *Client) ShareFolder(ctx context.Context, folderID string, permissions []Permission) error {
	err := checkUUIDFormat(folderID)
	if err != nil {
		return fmt.Errorf("Checking ID format: %w", err)
	}
	f := Folder{Permissions: permissions}
	_, err = c.DoCustomRequestV5(ctx, "PUT", "/share/folder/"+folderID+".json", f, nil)
	if err != nil {
		return err
	}

	return nil
}

// SimulateShareResource Simulates Shareing a Resource with AROs
func (c *Client) SimulateShareResource(ctx context.Context, resourceID string, shareRequest ResourceShareRequest) (*ResourceShareSimulationResult, error) {
	err := checkUUIDFormat(resourceID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequestV5(ctx, "POST", "/share/simulate/resource/"+resourceID+".json", shareRequest, nil)
	if err != nil {
		return nil, err
	}

	var res ResourceShareSimulationResult
	err = json.Unmarshal(msg.Body, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
