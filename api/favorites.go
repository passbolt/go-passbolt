package api

import (
	"context"
	"encoding/json"
	"fmt"
)

// Favorite is a Favorite
type Favorite struct {
	ID           string `json:"id,omitempty"`
	Created      *Time  `json:"created,omitempty"`
	ForeignKey   string `json:"foreign_key,omitempty"`
	ForeignModel string `json:"foreign_model,omitempty"`
	Modified     *Time  `json:"modified,omitempty"`
}

// CreateFavorite Creates a new Passbolt Favorite for the given Resource ID
func (c *Client) CreateFavorite(ctx context.Context, resourceID string) (*Favorite, error) {
	err := checkUUIDFormat(resourceID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequest(ctx, "POST", "/favorites/resource/"+resourceID+".json", nil, nil)
	if err != nil {
		return nil, err
	}

	var favorite Favorite
	err = json.Unmarshal(msg.Body, &favorite)
	if err != nil {
		return nil, err
	}
	return &favorite, nil
}

// DeleteFavorite Deletes a Passbolt Favorite
func (c *Client) DeleteFavorite(ctx context.Context, favoriteID string) error {
	err := checkUUIDFormat(favoriteID)
	if err != nil {
		return fmt.Errorf("Checking ID format: %w", err)
	}
	_, err = c.DoCustomRequest(ctx, "DELETE", "/favorites/"+favoriteID+".json", nil, nil)
	if err != nil {
		return err
	}
	return nil
}
