package helper

import "errors"

// ErrUnsupportedResourceType is returned when a resource has an unknown resource type slug
// that cannot be decoded by the helper functions.
var ErrUnsupportedResourceType = errors.New("unsupported resource type")

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
)
