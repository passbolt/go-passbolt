package helper

import "errors"

// ErrUnsupportedResourceType is returned when a resource has an unknown resource type slug
// that cannot be decoded by the helper functions.
var ErrUnsupportedResourceType = errors.New("unsupported resource type")
