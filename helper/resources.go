package helper

import (
	"context"
	"fmt"

	"github.com/passbolt/go-passbolt/api"
)

// DeleteResource Deletes a Resource
func DeleteResource(ctx context.Context, c *api.Client, resourceID string) error {
	err := c.DeleteResource(ctx, resourceID)
	if err != nil {
		return fmt.Errorf("Deleting Resource: %w", err)
	}
	return nil
}

// MoveResource Moves a Resource into a Folder
func MoveResource(ctx context.Context, c *api.Client, resourceID, folderParentID string) error {
	err := c.MoveResource(ctx, resourceID, folderParentID)
	if err != nil {
		return fmt.Errorf("Moveing Resource: %w", err)
	}
	return err
}
