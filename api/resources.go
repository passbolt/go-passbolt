package api

import (
	"context"
	"encoding/json"
	"fmt"
)

// Resource is a Resource.
// Warning: Since Passbolt v3 some fields here may not be populated as they may be in the Secret depending on the ResourceType,
// for now the only Field like that is the Decription.
type Resource struct {
	ID             string      `json:"id,omitempty"`
	Created        *Time       `json:"created,omitempty"`
	CreatedBy      string      `json:"created_by,omitempty"`
	Creator        *User       `json:"creator,omitempty"`
	Deleted        bool        `json:"deleted,omitempty"`
	Description    string      `json:"description,omitempty"`
	Favorite       *Favorite   `json:"favorite,omitempty"`
	Modified       *Time       `json:"modified,omitempty"`
	ModifiedBy     string      `json:"modified_by,omitempty"`
	Modifier       *User       `json:"modifier,omitempty"`
	Name           string      `json:"name,omitempty"`
	Permission     *Permission `json:"permission,omitempty"`
	URI            string      `json:"uri,omitempty"`
	Username       string      `json:"username,omitempty"`
	FolderParentID string      `json:"folder_parent_id,omitempty"`
	ResourceTypeID string      `json:"resource_type_id,omitempty"`
	Secrets        []Secret    `json:"secrets,omitempty"`
	Tags           []Tag       `json:"tags,omitempty"`
}

// Tag is a Passbolt Password Tag
type Tag struct {
	ID       string `json:"id,omitempty"`
	Slug     string `json:"slug,omitempty"`
	IsShared bool   `json:"is_shared,omitempty"`
}

// GetResourcesOptions are all available query parameters
type GetResourcesOptions struct {
	FilterIsFavorite        bool     `url:"filter[is-favorite],omitempty"`
	FilterIsSharedWithGroup []string `url:"filter[is-shared-with-group][],omitempty"`
	FilterIsOwnedByMe       bool     `url:"filter[is-owned-by-me],omitempty"`
	FilterIsSharedWithMe    bool     `url:"filter[is-shared-with-me],omitempty"`
	FilterHasID             []string `url:"filter[has-id][],omitempty"`
	// Parent Folder id
	FilterHasParent []string `url:"filter[has-parent][],omitempty"`
	FilterHasTag    string   `url:"filter[has-tag],omitempty"`

	ContainCreator                bool `url:"contain[creator],omitempty"`
	ContainFavorites              bool `url:"contain[favorite],omitempty"`
	ContainModifier               bool `url:"contain[modifier],omitempty"`
	ContainSecret                 bool `url:"contain[secret],omitempty"`
	ContainResourceType           bool `url:"contain[resource-type],omitempty"`
	ContainPermissions            bool `url:"contain[permission],omitempty"`
	ContainPermissionsUserProfile bool `url:"contain[permissions.user.profile],omitempty"`
	ContainPermissionsGroup       bool `url:"contain[permissions.group],omitempty"`
	ContainTags                   bool `url:"contain[tag],omitempty"`
}

// GetResources gets all Passbolt Resources
func (c *Client) GetResources(ctx context.Context, opts *GetResourcesOptions) ([]Resource, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/resources.json", "v2", nil, opts)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	err = json.Unmarshal(msg.Body, &resources)
	if err != nil {
		return nil, err
	}
	return resources, nil
}

// CreateResource Creates a new Passbolt Resource
func (c *Client) CreateResource(ctx context.Context, resource Resource) (*Resource, error) {
	msg, err := c.DoCustomRequest(ctx, "POST", "/resources.json", "v2", resource, nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(msg.Body, &resource)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetResource gets a Passbolt Resource
func (c *Client) GetResource(ctx context.Context, resourceID string) (*Resource, error) {
	err := checkUUIDFormat(resourceID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequest(ctx, "GET", "/resources/"+resourceID+".json", "v2", nil, nil)
	if err != nil {
		return nil, err
	}

	var resource Resource
	err = json.Unmarshal(msg.Body, &resource)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// UpdateResource Updates a existing Passbolt Resource
func (c *Client) UpdateResource(ctx context.Context, resourceID string, resource Resource) (*Resource, error) {
	err := checkUUIDFormat(resourceID)
	if err != nil {
		return nil, fmt.Errorf("Checking ID format: %w", err)
	}
	msg, err := c.DoCustomRequest(ctx, "PUT", "/resources/"+resourceID+".json", "v2", resource, nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(msg.Body, &resource)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// DeleteResource Deletes a Passbolt Resource
func (c *Client) DeleteResource(ctx context.Context, resourceID string) error {
	err := checkUUIDFormat(resourceID)
	if err != nil {
		return fmt.Errorf("Checking ID format: %w", err)
	}
	_, err = c.DoCustomRequest(ctx, "DELETE", "/resources/"+resourceID+".json", "v2", nil, nil)
	if err != nil {
		return err
	}
	return nil
}

// MoveResource Moves a Passbolt Resource
func (c *Client) MoveResource(ctx context.Context, resourceID, folderParentID string) error {
	err := checkUUIDFormat(resourceID)
	if err != nil {
		return fmt.Errorf("Checking ID format: %w", err)
	}
	_, err = c.DoCustomRequest(ctx, "PUT", "/move/resource/"+resourceID+".json", "v2", Resource{
		FolderParentID: folderParentID,
	}, nil)
	if err != nil {
		return err
	}
	return nil
}
