package api

import (
	"context"
	"encoding/json"
	"fmt"
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

// GetFoldersOptions are all available query parameters
type GetFoldersOptions struct {
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

	FilterHasID     []string `url:"filter[has-id][],omitempty"`
	FilterHasParent []string `url:"filter[has-parent][],omitempty"`
	FilterSearch    string   `url:"filter[search],omitempty"`
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
}

// GetFolders gets all Folders from the Passboltserver
func (c *Client) GetFolders(ctx context.Context, opts *GetFoldersOptions) ([]Folder, error) {
	msg, err := c.DoCustomRequestV5(ctx, "GET", "/folders.json", nil, opts)
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
	msg, err := c.DoCustomRequestV5(ctx, "POST", "/folders.json", folder, nil)
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
func (c *Client) GetFolder(ctx context.Context, folderID string, opts *GetFolderOptions) (*Folder, error) {
	err := checkUUIDFormat(folderID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequestV5(ctx, "GET", "/folders/"+folderID+".json", nil, opts)
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
	err := checkUUIDFormat(folderID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequestV5(ctx, "PUT", "/folders/"+folderID+".json", folder, nil)
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
	err := checkUUIDFormat(folderID)
	if err != nil {
		return fmt.Errorf("Checking ID format: %w", err)
	}
	_, err = c.DoCustomRequestV5(ctx, "DELETE", "/folders/"+folderID+".json", nil, nil)
	if err != nil {
		return err
	}
	return nil
}

// MoveFolder Moves a Passbolt Folder
func (c *Client) MoveFolder(ctx context.Context, folderID, folderParentID string) error {
	err := checkUUIDFormat(folderID)
	if err != nil {
		return fmt.Errorf("Checking ID format: %w", err)
	}
	_, err = c.DoCustomRequestV5(ctx, "PUT", "/move/folder/"+folderID+".json", Folder{
		FolderParentID: folderParentID,
	}, nil)
	if err != nil {
		return err
	}
	return nil
}
