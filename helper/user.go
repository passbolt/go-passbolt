package helper

import (
	"context"
	"fmt"

	"github.com/speatzle/go-passbolt/api"
)

// CreateUser Creates a new User
func CreateUser(ctx context.Context, c *api.Client, role, username, firstname, lastname string) (string, error) {
	roles, err := c.GetRoles(ctx)
	if err != nil {
		return "", fmt.Errorf("Get Role: %w", err)
	}

	roleID := ""

	for _, r := range roles {
		if r.Name == role {
			roleID = r.ID
			break
		}
	}

	if roleID == "" {
		return "", fmt.Errorf("Cannot Find Role: %v", role)
	}

	u, err := c.CreateUser(ctx, api.User{
		Username: username,
		Profile: &api.Profile{
			FirstName: firstname,
			LastName:  lastname,
		},
		RoleID: roleID,
	})
	if err != nil {
		return "", fmt.Errorf("Creating User: %w", err)
	}
	return u.ID, nil
}

// GetUser Gets a User
func GetUser(ctx context.Context, c *api.Client, userID string) (string, string, string, string, error) {
	u, err := c.GetUser(ctx, userID)
	if err != nil {
		return "", "", "", "", fmt.Errorf("Getting User: %w", err)
	}
	return u.Role.Name, u.Username, u.Profile.FirstName, u.Profile.LastName, nil
}

// UpdateUser Updates a User
func UpdateUser(ctx context.Context, c *api.Client, userID, role, firstname, lastname string) error {
	user, err := c.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("Getting User: %w", err)
	}

	new := api.User{
		Profile: &api.Profile{
			FirstName: user.Profile.FirstName,
			LastName:  user.Profile.LastName,
		},
	}

	if role != "" {
		roles, err := c.GetRoles(ctx)
		if err != nil {
			return fmt.Errorf("Get Role: %w", err)
		}

		roleID := ""

		for _, r := range roles {
			if r.Name == role {
				roleID = r.ID
				break
			}
		}

		if roleID == "" {
			return fmt.Errorf("Cannot Find Role %v", role)
		}
		new.RoleID = roleID
	}

	if firstname != "" {
		new.Profile.FirstName = firstname
	}
	if lastname != "" {
		new.Profile.LastName = lastname
	}

	_, err = c.UpdateUser(ctx, userID, new)
	if err != nil {
		return fmt.Errorf("Updating User: %w", err)
	}
	return nil
}

// DeleteUser Deletes a User
func DeleteUser(ctx context.Context, c *api.Client, userID string) error {
	err := c.DeleteUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("Deleting User: %w", err)
	}
	return nil
}
