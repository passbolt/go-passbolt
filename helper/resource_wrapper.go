package helper

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/passbolt/go-passbolt/api"
)

// Resource is a wrapper around api.Resource that provides unified access to resource data
// regardless of the resource type (v4 or v5). It uses lazy loading and caching for efficient
// access to encrypted data. Fields are stored as maps, driven by the resource type's JSON schema.
type Resource struct {
	client *api.Client
	raw    *api.Resource
	rType  *api.ResourceType

	// Lazy-loaded and cached raw data
	secretLoaded   bool
	metadataLoaded bool
	rawSecretData  string
	rawMetadata    string

	// Schema-driven field storage
	metadataFields map[string]any
	secretFields   map[string]any
	dataParsed     bool
}

// TOTP contains TOTP secret data
type TOTP struct {
	Algorithm string `json:"algorithm,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	Digits    int    `json:"digits,omitempty"`
	Period    int    `json:"period,omitempty"`
}

// NewResource creates a new Resource wrapper from an existing api.Resource.
// The client is required for decryption operations.
// The resource type will be fetched lazily if not provided.
func NewResource(client *api.Client, raw *api.Resource) *Resource {
	return &Resource{
		client: client,
		raw:    raw,
	}
}

// NewResourceWithType creates a new Resource wrapper with a known resource type.
// This avoids an extra API call to fetch the resource type.
func NewResourceWithType(client *api.Client, raw *api.Resource, rType *api.ResourceType) *Resource {
	return &Resource{
		client: client,
		raw:    raw,
		rType:  rType,
	}
}

// FetchResource fetches a resource by ID and returns a Resource wrapper.
func FetchResource(ctx context.Context, client *api.Client, resourceID string) (*Resource, error) {
	raw, err := client.GetResource(ctx, resourceID)
	if err != nil {
		return nil, fmt.Errorf("getting resource: %w", err)
	}

	return NewResource(client, raw), nil
}

// FetchResourceWithSecret fetches a resource by ID including its secret and returns a Resource wrapper.
// This is more efficient when you know you'll need the secret data.
func FetchResourceWithSecret(ctx context.Context, client *api.Client, resourceID string) (*Resource, error) {
	raw, err := client.GetResource(ctx, resourceID)
	if err != nil {
		return nil, fmt.Errorf("getting resource: %w", err)
	}

	r := NewResource(client, raw)

	// Pre-fetch the secret
	secret, err := client.GetSecret(ctx, resourceID)
	if err != nil {
		return nil, fmt.Errorf("getting secret: %w", err)
	}

	rawSecretData, err := client.DecryptMessage(secret.Data)
	if err != nil {
		return nil, fmt.Errorf("decrypting secret: %w", err)
	}

	r.rawSecretData = rawSecretData
	r.secretLoaded = true

	return r, nil
}

// Raw returns the underlying api.Resource
func (r *Resource) Raw() *api.Resource {
	return r.raw
}

// ID returns the resource ID
func (r *Resource) ID() string {
	return r.raw.ID
}

// FolderParentID returns the parent folder ID
func (r *Resource) FolderParentID() string {
	return r.raw.FolderParentID
}

// ResourceTypeID returns the resource type ID
func (r *Resource) ResourceTypeID() string {
	return r.raw.ResourceTypeID
}

// ensureResourceType ensures the resource type is loaded
func (r *Resource) ensureResourceType(ctx context.Context) error {
	if r.rType != nil {
		return nil
	}

	rType, err := r.client.GetResourceTypeCached(ctx, r.raw.ResourceTypeID)
	if err != nil {
		return fmt.Errorf("getting resource type: %w", err)
	}
	r.rType = rType
	return nil
}

// ensureSecretLoaded ensures the secret data is loaded and decrypted
func (r *Resource) ensureSecretLoaded(ctx context.Context) error {
	if r.secretLoaded {
		return nil
	}

	secret, err := r.client.GetSecret(ctx, r.raw.ID)
	if err != nil {
		return fmt.Errorf("getting secret: %w", err)
	}

	rawSecretData, err := r.client.DecryptMessage(secret.Data)
	if err != nil {
		return fmt.Errorf("decrypting secret: %w", err)
	}

	r.rawSecretData = rawSecretData
	r.secretLoaded = true
	return nil
}

// ensureMetadataLoaded ensures the metadata is loaded and decrypted (for v5 resources)
func (r *Resource) ensureMetadataLoaded(ctx context.Context) error {
	if r.metadataLoaded {
		return nil
	}

	if err := r.ensureResourceType(ctx); err != nil {
		return err
	}

	// Only v5 resources have encrypted metadata
	if !r.isV5Resource() {
		r.metadataLoaded = true
		return nil
	}

	rawMetadata, err := r.getResourceMetadataCached(ctx)
	if err != nil {
		return fmt.Errorf("getting metadata: %w", err)
	}

	r.rawMetadata = rawMetadata
	r.metadataLoaded = true
	return nil
}

// getResourceMetadataCached gets resource metadata using cached decrypted keys
func (r *Resource) getResourceMetadataCached(ctx context.Context) (string, error) {
	var metadataKeyID string

	if r.raw.MetadataKeyType == api.MetadataKeyTypeUserKey {
		metadataKey, err := r.client.GetUserPrivateKeyCopy()
		if err != nil {
			return "", fmt.Errorf("get private key copy: %w", err)
		}
		// For user keys, we don't cache session keys (the key ID is unique per user)
		return r.client.DecryptMetadata(metadataKey, r.raw.Metadata)
	}

	// Use cached decrypted metadata key
	metadataKeyID = r.raw.MetadataKeyID
	metadataKey, err := r.client.GetDecryptedMetadataKeyCached(ctx, metadataKeyID)
	if err != nil {
		return "", fmt.Errorf("get metadata key by ID: %w", err)
	}

	// Use the new function that caches session keys
	return r.client.DecryptMetadataWithKeyID(metadataKeyID, metadataKey, r.raw.Metadata)
}

// isV5Resource returns true if this is a v5 resource type.
// Detection is based on the presence of encrypted metadata on the resource.
func (r *Resource) isV5Resource() bool {
	return r.raw.Metadata != ""
}

// ensureDataParsed parses metadata and secret data into maps, driven by the resource type schema.
// This replaces the old switch-based ensureBasicFieldsParsed with a generic approach.
func (r *Resource) ensureDataParsed(ctx context.Context) error {
	if r.dataParsed {
		return nil
	}

	if err := r.ensureResourceType(ctx); err != nil {
		return err
	}

	if err := r.ensureSecretLoaded(ctx); err != nil {
		return err
	}

	if err := r.ensureMetadataLoaded(ctx); err != nil {
		return err
	}

	// Parse metadata
	if r.isV5Resource() {
		// V5: metadata is encrypted JSON
		r.metadataFields = make(map[string]any)
		if r.rawMetadata != "" {
			if err := json.Unmarshal([]byte(r.rawMetadata), &r.metadataFields); err != nil {
				return fmt.Errorf("parsing Metadata: %w", err)
			}
		}
	} else {
		// V4: metadata is in cleartext fields on the resource
		r.metadataFields = map[string]any{
			"name":        r.raw.Name,
			"username":    r.raw.Username,
			"uri":         r.raw.URI,
			"description": r.raw.Description,
		}
	}

	// Parse secret
	if r.rType.IsSecretString() {
		// Secret is a plain string (password-string, v5-password-string)
		r.secretFields = map[string]any{
			"password": r.rawSecretData,
		}
	} else {
		// Secret is JSON
		r.secretFields = make(map[string]any)
		if r.rawSecretData != "" {
			if err := json.Unmarshal([]byte(r.rawSecretData), &r.secretFields); err != nil {
				return fmt.Errorf("parsing Secret Data: %w", err)
			}
		}
	}

	r.dataParsed = true
	return nil
}

// ensureMetadataParsed parses only metadata, useful when secret is not needed.
func (r *Resource) ensureMetadataParsed(ctx context.Context) error {
	if r.dataParsed || r.metadataFields != nil {
		return nil
	}

	if err := r.ensureResourceType(ctx); err != nil {
		return err
	}

	if err := r.ensureMetadataLoaded(ctx); err != nil {
		return err
	}

	if r.isV5Resource() {
		r.metadataFields = make(map[string]any)
		if r.rawMetadata != "" {
			if err := json.Unmarshal([]byte(r.rawMetadata), &r.metadataFields); err != nil {
				return fmt.Errorf("parsing Metadata: %w", err)
			}
		}
	} else {
		r.metadataFields = map[string]any{
			"name":        r.raw.Name,
			"username":    r.raw.Username,
			"uri":         r.raw.URI,
			"description": r.raw.Description,
		}
	}

	return nil
}

// Name returns the resource name
func (r *Resource) Name(ctx context.Context) (string, error) {
	if err := r.ensureMetadataParsed(ctx); err != nil {
		return "", err
	}
	return getStringField(r.metadataFields, "name"), nil
}

// Username returns the username
func (r *Resource) Username(ctx context.Context) (string, error) {
	if err := r.ensureMetadataParsed(ctx); err != nil {
		return "", err
	}
	return getStringField(r.metadataFields, "username"), nil
}

// URI returns the URI (handles both v4 "uri" string and v5 "uris" array)
func (r *Resource) URI(ctx context.Context) (string, error) {
	if err := r.ensureMetadataParsed(ctx); err != nil {
		return "", err
	}
	// V4: "uri" field
	if uri := getStringField(r.metadataFields, "uri"); uri != "" {
		return uri, nil
	}
	// V5: "uris" array
	if uris, ok := r.metadataFields["uris"].([]any); ok && len(uris) > 0 {
		if s, ok := uris[0].(string); ok {
			return s, nil
		}
	}
	return "", nil
}

// Password returns the password
func (r *Resource) Password(ctx context.Context) (string, error) {
	if err := r.ensureDataParsed(ctx); err != nil {
		return "", err
	}
	return getStringField(r.secretFields, "password"), nil
}

// Description returns the description.
// Description can live in metadata or secret depending on the resource type.
func (r *Resource) Description(ctx context.Context) (string, error) {
	if err := r.ensureDataParsed(ctx); err != nil {
		return "", err
	}
	// Check metadata first (where v5-password-string and v4 store it)
	if desc := getStringField(r.metadataFields, "description"); desc != "" {
		return desc, nil
	}
	// Fall back to secret (where v5-default stores it)
	return getStringField(r.secretFields, "description"), nil
}

// TOTP returns the TOTP data if available, nil otherwise
func (r *Resource) TOTP(ctx context.Context) (*TOTP, error) {
	if err := r.ensureDataParsed(ctx); err != nil {
		return nil, err
	}
	totpRaw, ok := r.secretFields["totp"]
	if !ok {
		return nil, nil
	}
	totpMap, ok := totpRaw.(map[string]any)
	if !ok {
		return nil, nil
	}
	totp := &TOTP{
		Algorithm: getStringField(totpMap, "algorithm"),
		SecretKey: getStringField(totpMap, "secret_key"),
	}
	if d, ok := totpMap["digits"].(float64); ok {
		totp.Digits = int(d)
	}
	if p, ok := totpMap["period"].(float64); ok {
		totp.Period = int(p)
	}
	return totp, nil
}

// HasTOTP returns true if this resource has TOTP data
func (r *Resource) HasTOTP(ctx context.Context) (bool, error) {
	totp, err := r.TOTP(ctx)
	if err != nil {
		return false, err
	}
	return totp != nil, nil
}

// GetAll returns all basic fields at once, similar to the old GetResource function
func (r *Resource) GetAll(ctx context.Context) (folderParentID, name, username, uri, password, description string, err error) {
	if err := r.ensureDataParsed(ctx); err != nil {
		return "", "", "", "", "", "", err
	}
	n, _ := r.Name(ctx)
	u, _ := r.Username(ctx)
	ur, _ := r.URI(ctx)
	p, _ := r.Password(ctx)
	d, _ := r.Description(ctx)
	return r.raw.FolderParentID, n, u, ur, p, d, nil
}

// MetadataField returns a single field from the metadata map
func (r *Resource) MetadataField(ctx context.Context, key string) (any, error) {
	if err := r.ensureMetadataParsed(ctx); err != nil {
		return nil, err
	}
	return r.metadataFields[key], nil
}

// SecretField returns a single field from the secret map
func (r *Resource) SecretField(ctx context.Context, key string) (any, error) {
	if err := r.ensureDataParsed(ctx); err != nil {
		return nil, err
	}
	return r.secretFields[key], nil
}

// MetadataFields returns a copy of all metadata fields
func (r *Resource) MetadataFields(ctx context.Context) (map[string]any, error) {
	if err := r.ensureMetadataParsed(ctx); err != nil {
		return nil, err
	}
	result := make(map[string]any, len(r.metadataFields))
	for k, v := range r.metadataFields {
		result[k] = v
	}
	return result, nil
}

// SecretFields returns a copy of all secret fields
func (r *Resource) SecretFields(ctx context.Context) (map[string]any, error) {
	if err := r.ensureDataParsed(ctx); err != nil {
		return nil, err
	}
	result := make(map[string]any, len(r.secretFields))
	for k, v := range r.secretFields {
		result[k] = v
	}
	return result, nil
}

// ResourceType returns the resource type
func (r *Resource) ResourceType(ctx context.Context) (*api.ResourceType, error) {
	if err := r.ensureResourceType(ctx); err != nil {
		return nil, err
	}
	return r.rType, nil
}

// ResourceTypeSlug returns the resource type slug
func (r *Resource) ResourceTypeSlug(ctx context.Context) (string, error) {
	rType, err := r.ResourceType(ctx)
	if err != nil {
		return "", err
	}
	return rType.Slug, nil
}

// getStringField safely extracts a string from a map
func getStringField(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
