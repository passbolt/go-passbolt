package api

import (
	"context"
	"encoding/json"
	"fmt"
)

// Comment is a Comment
type Comment struct {
	ID           string    `json:"id,omitempty"`
	ParentID     string    `json:"parent_id,omitempty"`
	ForeignKey   string    `json:"foreign_key,omitempty"`
	Content      string    `json:"content,omitempty"`
	ForeignModel string    `json:"foreign_model,omitempty"`
	Created      *Time     `json:"created,omitempty"`
	CreatedBy    string    `json:"created_by,omitempty"`
	UserID       string    `json:"user_id,omitempty"`
	Description  string    `json:"description,omitempty"`
	Modified     *Time     `json:"modified,omitempty"`
	ModifiedBy   string    `json:"modified_by,omitempty"`
	Children     []Comment `json:"children,omitempty"`
}

// GetCommentsOptions are all available query parameters
type GetCommentsOptions struct {
	ContainCreator  bool `url:"contain[creator],omitempty"`
	ContainModifier bool `url:"contain[modifier],omitempty"`
}

// GetComments gets all Passbolt Comments an The Specified Resource
func (c *Client) GetComments(ctx context.Context, resourceID string, opts *GetCommentsOptions) ([]Comment, error) {
	err := checkUUIDFormat(resourceID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequest(ctx, "GET", "/comments/resource/"+resourceID+".json", nil, opts)
	if err != nil {
		return nil, err
	}

	var comments []Comment
	err = json.Unmarshal(msg.Body, &comments)
	if err != nil {
		return nil, err
	}
	return comments, nil
}

// CreateComment Creates a new Passbolt Comment
func (c *Client) CreateComment(ctx context.Context, resourceID string, comment Comment) (*Comment, error) {
	err := checkUUIDFormat(resourceID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequest(ctx, "POST", "/comments/resource/"+resourceID+".json", comment, nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(msg.Body, &comment)
	if err != nil {
		return nil, err
	}
	return &comment, nil
}

// UpdateComment Updates a existing Passbolt Comment
func (c *Client) UpdateComment(ctx context.Context, commentID string, comment Comment) (*Comment, error) {
	err := checkUUIDFormat(commentID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequest(ctx, "PUT", "/comments/"+commentID+".json", comment, nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(msg.Body, &comment)
	if err != nil {
		return nil, err
	}
	return &comment, nil
}

// DeleteComment Deletes a Passbolt Comment
func (c *Client) DeleteComment(ctx context.Context, commentID string) error {
	err := checkUUIDFormat(commentID)
	if err != nil {
		return fmt.Errorf("Checking ID format: %w", err)
	}
	_, err = c.DoCustomRequest(ctx, "DELETE", "/comments/"+commentID+".json", nil, nil)
	if err != nil {
		return err
	}
	return nil
}
