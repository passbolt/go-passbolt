package passbolt

import (
	"context"
	"encoding/json"
)

// ResourceShareRequest is a ResourceShareRequest
type ResourceShareRequest struct {
	Permissions []Permission `json:"permissions,omitempty"`
	Secrets     []Secret     `json:"secrets,omitempty"`
}

// ResourceShareSimulationResult is the Result of a Sharing Siumulation
type ResourceShareSimulationResult struct {
	Changes ResourceShareSimulationChanges `json:"changes,omitempty"`
}

type ResourceShareSimulationChanges struct {
	Added   []ResourceShareSimulationChange `json:"added,omitempty"`
	Removed []ResourceShareSimulationChange `json:"removed,omitempty"`
}

type ResourceShareSimulationChange struct {
	User ResourceShareSimulationUser `json:"user,omitempty"`
}

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
	msg, err := c.DoCustomRequest(ctx, "GET", "/share/search-aros.json", "v2", nil, opts)
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
	_, err := c.DoCustomRequest(ctx, "PUT", "/share/resource/"+resourceID+".json", "v2", shareRequest, nil)
	if err != nil {
		return err
	}

	return nil
}

// ShareFolder Shares a Folder with AROs
func (c *Client) ShareFolder(ctx context.Context, folderID string, permissions []Permission) error {
	f := Folder{Permissions: permissions}
	_, err := c.DoCustomRequest(ctx, "PUT", "/share/folder/"+folderID+".json", "v2", f, nil)
	if err != nil {
		return err
	}

	return nil
}

// SimulateShareResource Simulates Shareing a Resource with AROs
func (c *Client) SimulateShareResource(ctx context.Context, resourceID string, shareRequest ResourceShareRequest) (*ResourceShareSimulationResult, error) {
	msg, err := c.DoCustomRequest(ctx, "POST", "/share/simulate/resource/"+resourceID+".json", "v2", shareRequest, nil)
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
