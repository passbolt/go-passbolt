package api

import (
	"context"
	"encoding/json"
)

type PassboltAPIVersionType string

const (
	PassboltAPIVersionTypeV4 PassboltAPIVersionType = "v4"
	PassboltAPIVersionTypeV5                        = "v5"
)

func (s PassboltAPIVersionType) IsValid() bool {
	switch s {
	case PassboltAPIVersionTypeV4, PassboltAPIVersionTypeV5:
		return true
	}
	return false
}

// MetadataTypeSettings Contains the Servers Settings about which Types to use
type MetadataTypeSettings struct {
	DefaultResourceType        PassboltAPIVersionType `json:"default_resource_types"`
	DefaultFolderType          PassboltAPIVersionType `json:"default_folder_type"`
	DefaultTagType             PassboltAPIVersionType `json:"default_tag_type"`
	DefaultCommentType         PassboltAPIVersionType `json:"default_comment_type"`
	AllowCreationOfV5Resources bool                   `json:"allow_creation_of_v5_resources"`
	AllowCreationOfV5Folders   bool                   `json:"allow_creation_of_v5_folders"`
	AllowCreationOfV5Tags      bool                   `json:"allow_creation_of_v5_tags"`
	AllowCreationOfV5Comments  bool                   `json:"allow_creation_of_v5_comments"`
	AllowCreationOfV4Resources bool                   `json:"allow_creation_of_v4_resources"`
	AllowCreationOfV4Folders   bool                   `json:"allow_creation_of_v4_folders"`
	AllowCreationOfV4Tags      bool                   `json:"allow_creation_of_v4_tags"`
	AllowCreationOfV4Comments  bool                   `json:"allow_creation_of_v4_comments"`
	AllowV4V5Upgrade           bool                   `json:"allow_v4_v5_upgrade"`
	AllowV4V5Downgrade         bool                   `json:"allow_v5_v4_downgrade"`
}

func getV4DefaultMetadataTypeSettings() MetadataTypeSettings {
	return MetadataTypeSettings{
		DefaultResourceType:        PassboltAPIVersionTypeV4,
		DefaultFolderType:          PassboltAPIVersionTypeV4,
		DefaultTagType:             PassboltAPIVersionTypeV4,
		DefaultCommentType:         PassboltAPIVersionTypeV4,
		AllowCreationOfV5Resources: false,
		AllowCreationOfV5Folders:   false,
		AllowCreationOfV5Tags:      false,
		AllowCreationOfV5Comments:  false,
		AllowCreationOfV4Resources: true,
		AllowCreationOfV4Folders:   true,
		AllowCreationOfV4Tags:      true,
		AllowCreationOfV4Comments:  true,
		AllowV4V5Upgrade:           false,
		AllowV4V5Downgrade:         false,
	}
}

// GetMetadataTypeSettings gets the Servers Settings about which Types to use
func (c *Client) GetMetadataTypeSettings(ctx context.Context) (*MetadataTypeSettings, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/metadata/types/settings.json", "v3", nil, nil)
	if err != nil {
		return nil, err
	}

	var metadataSettings MetadataTypeSettings
	err = json.Unmarshal(msg.Body, &metadataSettings)
	if err != nil {
		return nil, err
	}
	return &metadataSettings, nil
}
