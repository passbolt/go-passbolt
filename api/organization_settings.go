package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

// OrganizationSettingsPlugin describes operations implemented by this client.
// A server may restrict them further based on its edition, enabled plugins and
// the authenticated user's permissions.
type OrganizationSettingsPlugin struct {
	Name             string `json:"name"`
	Readable         bool   `json:"readable"`
	Writable         bool   `json:"writable"`
	Deletable        bool   `json:"deletable"`
	DeleteRequiresID bool   `json:"delete_requires_id"`
}

type organizationSettingsDeleteMode uint8

const (
	organizationSettingsNoDelete organizationSettingsDeleteMode = iota
	organizationSettingsDeleteSingleton
	organizationSettingsDeleteByID
)

type organizationSettingsSpec struct {
	name, path         string
	readable, writable bool
	deleteMode         organizationSettingsDeleteMode
}

// Paths and methods follow the CE/EE plugin routes. In particular, settings are
// not interchangeable rows exposed through a generic organization_settings API.
var organizationSettingsSpecs = [...]organizationSettingsSpec{
	{"account-recovery-policies", "/account-recovery/organization-policies", true, true, organizationSettingsNoDelete},
	{"directory-sync", "/directorysync/settings", true, true, organizationSettingsDeleteSingleton},
	{"email-notifications", "/settings/emails/notifications", true, true, organizationSettingsNoDelete},
	{"export-policies", "/export-policies/settings", true, false, organizationSettingsNoDelete},
	{"locale", "/locale/settings", false, true, organizationSettingsNoDelete},
	{"metadata-keys", "/metadata/keys/settings", true, true, organizationSettingsNoDelete},
	{"metadata-types", "/metadata/types/settings", true, true, organizationSettingsNoDelete},
	{"mfa", "/mfa/settings", true, true, organizationSettingsNoDelete},
	{"mfa-policies", "/mfa-policies/settings", true, true, organizationSettingsNoDelete},
	{"password-expiry", "/password-expiry/settings", true, true, organizationSettingsDeleteByID},
	{"password-policies", "/password-policies/settings", true, true, organizationSettingsNoDelete},
	{"scim", "/scim/settings", true, true, organizationSettingsDeleteByID},
	{"secret-revisions", "/secret-revisions/settings", true, true, organizationSettingsDeleteSingleton},
	{"self-registration", "/self-registration/settings", true, true, organizationSettingsDeleteByID},
	{"smtp", "/smtp/settings", true, true, organizationSettingsNoDelete},
	{"sso", "/sso/settings", true, true, organizationSettingsDeleteByID},
	{"user-key-policies", "/user-key-policies/settings", true, false, organizationSettingsNoDelete},
	{"user-passphrase-policies", "/user-passphrase-policies/settings", true, true, organizationSettingsNoDelete},
}

// OrganizationSettingsPlugins returns an independent, sorted list of the
// supported plugin names and their operations. It does not contact the server.
func OrganizationSettingsPlugins() []OrganizationSettingsPlugin {
	result := make([]OrganizationSettingsPlugin, 0, len(organizationSettingsSpecs))
	for _, spec := range organizationSettingsSpecs {
		result = append(result, OrganizationSettingsPlugin{
			Name: spec.name, Readable: spec.readable, Writable: spec.writable,
			Deletable:        spec.deleteMode != organizationSettingsNoDelete,
			DeleteRequiresID: spec.deleteMode == organizationSettingsDeleteByID,
		})
	}
	return result
}

func findOrganizationSettingsSpec(plugin string) (organizationSettingsSpec, error) {
	for _, spec := range organizationSettingsSpecs {
		if spec.name == plugin {
			return spec, nil
		}
	}
	return organizationSettingsSpec{}, fmt.Errorf("unknown organization settings plugin %q", plugin)
}

// GetOrganizationSettings reads the plugin-specific response body as JSON.
// It preserves all server fields without flattening or normalizing their names.
func (c *Client) GetOrganizationSettings(ctx context.Context, plugin string) (json.RawMessage, error) {
	spec, err := findOrganizationSettingsSpec(plugin)
	if err != nil {
		return nil, err
	}
	if !spec.readable {
		return nil, fmt.Errorf("organization settings plugin %q does not support reading", plugin)
	}
	response, err := c.DoCustomRequestV5(ctx, "GET", spec.path+".json", nil, nil)
	if err != nil {
		return nil, err
	}
	return response.Body, nil
}

// SetOrganizationSettings submits a plugin-specific JSON object. The server
// validates its schema and access permissions. Payloads must already use the
// API's field names and any required encryption/signatures; this method does
// not encrypt credentials, activate SSO settings or perform metadata migrations.
// Read responses can contain server-only fields and are not necessarily valid
// update payloads. Log in again to refresh the client's cached server settings
// before performing other operations affected by a settings change.
func (c *Client) SetOrganizationSettings(ctx context.Context, plugin string, settings json.RawMessage) (json.RawMessage, error) {
	spec, err := findOrganizationSettingsSpec(plugin)
	if err != nil {
		return nil, err
	}
	if !spec.writable {
		return nil, fmt.Errorf("organization settings plugin %q does not support writing", plugin)
	}
	settings = bytes.TrimSpace(settings)
	if !json.Valid(settings) || len(settings) == 0 || settings[0] != '{' {
		return nil, fmt.Errorf("organization settings must be a JSON object")
	}
	response, err := c.DoCustomRequestV5(ctx, "POST", spec.path+".json", settings, nil)
	if err != nil {
		return nil, err
	}
	return response.Body, nil
}

// DeleteOrganizationSettings deletes or disables settings using the plugin's
// supported endpoint. For record-specific endpoints, settingsID must be a UUID
// returned by the settings API; singleton endpoints require an empty settingsID.
// Log in again to refresh cached server settings before subsequent operations.
func (c *Client) DeleteOrganizationSettings(ctx context.Context, plugin, settingsID string) error {
	spec, err := findOrganizationSettingsSpec(plugin)
	if err != nil {
		return err
	}
	path := spec.path
	switch spec.deleteMode {
	case organizationSettingsDeleteByID:
		if err := checkUUIDFormat(settingsID); err != nil {
			return fmt.Errorf("checking settings ID format: %w", err)
		}
		path += "/" + settingsID
	case organizationSettingsDeleteSingleton:
		if settingsID != "" {
			return fmt.Errorf("organization settings plugin %q does not accept a settings ID", plugin)
		}
	default:
		return fmt.Errorf("organization settings plugin %q does not support deletion", plugin)
	}
	_, err = c.DoCustomRequestV5(ctx, "DELETE", path+".json", nil, nil)
	return err
}
