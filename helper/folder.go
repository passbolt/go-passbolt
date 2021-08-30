package helper

import (
	"context"

	"github.com/speatzle/go-passbolt"
)

func CreateFolder(ctx context.Context, c *passbolt.Client, folderParentID, name string) (string, error) {
	f, err := c.CreateFolder(ctx, passbolt.Folder{
		Name:           name,
		FolderParentID: folderParentID,
	})
	return f.ID, err
}

func GetFolder(ctx context.Context, c *passbolt.Client, folderID string) (string, string, error) {
	f, err := c.GetFolder(ctx, folderID)
	return f.FolderParentID, f.Name, err
}

func UpdateFolder(ctx context.Context, c *passbolt.Client, folderID, name string) error {
	_, err := c.UpdateFolder(ctx, folderID, passbolt.Folder{Name: name})
	return err
}

func DeleteFolder(ctx context.Context, c *passbolt.Client, folderID string) error {
	return c.DeleteFolder(ctx, folderID)
}

func MoveFolder(ctx context.Context, c *passbolt.Client, folderID, folderParentID string) error {
	return c.MoveFolder(ctx, folderID, folderParentID)
}
