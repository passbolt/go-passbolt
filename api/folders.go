package api

import (
	"context"
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
	return doList[Folder](ctx, c, "/folders.json", opts)
}

// CreateFolder Creates a new Passbolt Folder
func (c *Client) CreateFolder(ctx context.Context, folder Folder) (*Folder, error) {
	return doSave(ctx, c, "POST", "/folders.json", folder)
}

// GetFolder gets a Passbolt Folder
func (c *Client) GetFolder(ctx context.Context, folderID string, opts *GetFolderOptions) (*Folder, error) {
	if err := checkUUIDFormat(folderID); err != nil {
		return nil, fmt.Errorf("checking ID format: %w", err)
	}
	return doInto[Folder](ctx, c, "GET", "/folders/"+folderID+".json", nil, opts)
}

// UpdateFolder Updates a existing Passbolt Folder
func (c *Client) UpdateFolder(ctx context.Context, folderID string, folder Folder) (*Folder, error) {
	if err := checkUUIDFormat(folderID); err != nil {
		return nil, fmt.Errorf("checking ID format: %w", err)
	}
	return doSave(ctx, c, "PUT", "/folders/"+folderID+".json", folder)
}

// DeleteFolder Deletes a Passbolt Folder
func (c *Client) DeleteFolder(ctx context.Context, folderID string) error {
	if err := checkUUIDFormat(folderID); err != nil {
		return fmt.Errorf("checking ID format: %w", err)
	}
	return doDelete(ctx, c, "/folders/"+folderID+".json")
}

// MoveFolder Moves a Passbolt Folder
func (c *Client) MoveFolder(ctx context.Context, folderID, folderParentID string) error {
	err := checkUUIDFormat(folderID)
	if err != nil {
		return fmt.Errorf("checking ID format: %w", err)
	}
	_, err = c.DoCustomRequest(ctx, "PUT", "/move/folder/"+folderID+".json", "v2", Folder{
		FolderParentID: folderParentID,
	}, nil)
	if err != nil {
		return err
	}
	return nil
}
