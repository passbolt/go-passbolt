package api

import (
	"context"
	"encoding/json"
)

// Folder is a Folder
type Folder struct {
	ID                string       `json:"id,omitempty"`
	Created           *Time        `json:"created,omitempty"`
	CreatedBy         string       `json:"created_by,omitempty"`
	Modified          *Time        `json:"modified,omitempty"`
	ModifiedBy        string       `json:"modified_by,omitempty"`
	Name              string       `json:"name,omitempty"`
	Permissions       []Permission `json:"permissions,omitempty"`
	FolderParentID    string       `json:"folder_parent_id,omitempty"`
	Personal          bool         `json:"personal,omitempty"`
	ChildrenResources []Resource   `json:"children_resources,omitempty"`
	ChildrenFolders   []Folder     `json:"children_folders,omitempty"`
}

// GetFolderOptions are all available query parameters
type GetFolderOptions struct {
	ContainChildrenResources     bool `url:"contain[children_resources],omitempty"`
	ContainChildrenFolders       bool `url:"contain[children_folders],omitempty"`
	ContainCreator               bool `url:"contain[creator],omitempty"`
	ContainCreatorProfile        bool `url:"contain[creator.profile],omitempty"`
	ContainModifier              bool `url:"contain[modifier],omitempty"`
	ContainModiferProfile        bool `url:"contain[modifier.profile],omitempty"`
	ContainPermission            bool `url:"contain[permission],omitempty"`
	ContainPermissions           bool `url:"contain[permissions],omitempty"`
	ContainPermissionUserProfile bool `url:"contain[permissions.user.profile],omitempty"`
	ContainPermissionGroup       bool `url:"contain[permissions.group],omitempty"`

	FilterHasID     string `url:"filter[has-id][],omitempty"`
	FilterHasParent string `url:"filter[has-parent][],omitempty"`
	FilterSearch    string `url:"filter[search],omitempty"`
}

// GetFolders gets all Folders from the Passboltserver
func (c *Client) GetFolders(ctx context.Context, opts *GetFolderOptions) ([]Folder, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/folders.json", "v2", nil, opts)
	if err != nil {
		return nil, err
	}

	var body []Folder
	err = json.Unmarshal(msg.Body, &body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// CreateFolder Creates a new Passbolt Folder
func (c *Client) CreateFolder(ctx context.Context, folder Folder) (*Folder, error) {
	msg, err := c.DoCustomRequest(ctx, "POST", "/folders.json", "v2", folder, nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(msg.Body, &folder)
	if err != nil {
		return nil, err
	}
	return &folder, nil
}

// GetFolder gets a Passbolt Folder
func (c *Client) GetFolder(ctx context.Context, folderID string) (*Folder, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/folders/"+folderID+".json", "v2", nil, nil)
	if err != nil {
		return nil, err
	}

	var folder Folder
	err = json.Unmarshal(msg.Body, &folder)
	if err != nil {
		return nil, err
	}
	return &folder, nil
}

// UpdateFolder Updates a existing Passbolt Folder
func (c *Client) UpdateFolder(ctx context.Context, folderID string, folder Folder) (*Folder, error) {
	msg, err := c.DoCustomRequest(ctx, "PUT", "/folders/"+folderID+".json", "v2", folder, nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(msg.Body, &folder)
	if err != nil {
		return nil, err
	}
	return &folder, nil
}

// DeleteFolder Deletes a Passbolt Folder
func (c *Client) DeleteFolder(ctx context.Context, folderID string) error {
	_, err := c.DoCustomRequest(ctx, "DELETE", "/folders/"+folderID+".json", "v2", nil, nil)
	if err != nil {
		return err
	}
	return nil
}

// MoveFolder Moves a Passbolt Folder
func (c *Client) MoveFolder(ctx context.Context, folderID, folderParentID string) error {
	_, err := c.DoCustomRequest(ctx, "PUT", "/move/folder/"+folderID+".json", "v2", Folder{
		FolderParentID: folderParentID,
	}, nil)
	if err != nil {
		return err
	}
	return nil
}
