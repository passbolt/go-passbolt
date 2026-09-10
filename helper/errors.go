package helper

import (
	"errors"
	"fmt"
)

// ErrUnsupportedResourceType is returned when a resource has an unknown resource type slug
// that cannot be decoded by the helper functions.
var ErrUnsupportedResourceType = errors.New("unsupported resource type")

// ErrSchemaValidation is returned when a document fails validation against the bundled Resource
// Type schema, on the read path as well as the write path. Lenient read validation still enforces
// every declared constraint, so a stored value this build's schema rejects fails here too.
var ErrSchemaValidation = errors.New("data does not match the bundled Resource Type schema")

// ErrSchemaMismatch is the write-path case of ErrSchemaValidation: the document carries
// properties the schema does not declare, either because of a wrong field name or because the
// bundled schema is older than the server's Resource Type. errors.Is reports ErrSchemaValidation
// for it too.
var ErrSchemaMismatch = fmt.Errorf("%w: it has undeclared properties", ErrSchemaValidation)

var (
	// Resource creation errors
	ErrV5CreationDisabled       = errors.New("creation of V5 passwords is disabled on this server")
	ErrV4CreationDisabled       = errors.New("creation of V4 passwords is disabled on this server")
	ErrResourceTypeSlugNotFound = errors.New("cannot find resource type")
	ErrPasswordTooLong          = errors.New("password exceeds maximum length")

	// Lookup errors
	ErrKeyNotFound        = errors.New("cannot find key for user")
	ErrMembershipNotFound = errors.New("cannot find membership for user")
	ErrSecretNotFound     = errors.New("cannot find secret for resource")

	// Custom field validation errors
	ErrCustomFieldInvalidID    = errors.New("custom field id must be a valid UUID")
	ErrCustomFieldMissingKey   = errors.New("custom field in metadata must have metadata_key")
	ErrCustomFieldMissingValue = errors.New("custom field in secret must have secret_value")
	ErrCustomFieldCrossField   = errors.New("custom field key/value must be defined in only one of metadata or secret")
	ErrCustomFieldIDMismatch   = errors.New("custom field ids must match in metadata and secret arrays")
)
