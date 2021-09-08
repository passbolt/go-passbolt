package helper

import (
	"context"
	"fmt"

	"github.com/speatzle/go-passbolt/api"
)

// CreateFolder Creates a new Folder
func CreateFolder(ctx context.Context, c *api.Client, folderParentID, name string) (string, error) {
	f, err := c.CreateFolder(ctx, api.Folder{
		Name:           name,
		FolderParentID: folderParentID,
	})
	if err != nil {
		return "", fmt.Errorf("Creating Folder: %w", err)
	}
	return f.ID, nil
}

// GetFolder Gets a Folder
func GetFolder(ctx context.Context, c *api.Client, folderID string) (string, string, error) {
	f, err := c.GetFolder(ctx, folderID)
	if err != nil {
		return "", "", fmt.Errorf("Getting Folder: %w", err)
	}
	return f.FolderParentID, f.Name, nil
}

// UpdateFolder Updates a Folder
func UpdateFolder(ctx context.Context, c *api.Client, folderID, name string) error {
	_, err := c.UpdateFolder(ctx, folderID, api.Folder{Name: name})
	if err != nil {
		return fmt.Errorf("Updating Folder: %w", err)
	}
	return err
}

// DeleteFolder Deletes a Folder
func DeleteFolder(ctx context.Context, c *api.Client, folderID string) error {
	err := c.DeleteFolder(ctx, folderID)
	if err != nil {
		return fmt.Errorf("Deleting Folder: %w", err)
	}
	return nil
}

// MoveFolder Moves a Folder into a Folder
func MoveFolder(ctx context.Context, c *api.Client, folderID, folderParentID string) error {
	err := c.MoveFolder(ctx, folderID, folderParentID)
	if err != nil {
		return fmt.Errorf("Moving Folder: %w", err)
	}
	return nil
}
