package api

import (
	"errors"
	"fmt"
)

// ErrAPIResponseErrorStatusCode indicates the API returned an error status.
//
// Deprecated: Use errors.As with *APIError instead.
var ErrAPIResponseErrorStatusCode = errors.New("error API JSON Response Status")

// ErrAPIResponseUnknownStatusCode indicates the API returned an unknown status.
//
// Deprecated: Use errors.As with *APIError instead.
var ErrAPIResponseUnknownStatusCode = errors.New("unknown API JSON Response Status")

var (
	// Authentication & session errors
	ErrNoPrivateKey       = errors.New("client has no user private key")
	ErrSessionNotFound    = errors.New("cannot find session cookie")
	ErrEmptyAuthToken     = errors.New("got empty X-GPGAuth-User-Auth-Token header")
	ErrMFAFailed          = errors.New("MFA challenge failed")
	ErrMFACallbackMissing = errors.New("MFA callback is not defined")

	// Data lookup errors
	ErrResourceTypeNotFound = errors.New("resource type not found")
	ErrMetadataKeyNotFound  = errors.New("metadata key not found")
	ErrNoMetadataPrivateKey = errors.New("no metadata private key for user")
	ErrInvalidUUID          = errors.New("UUID is not in valid format")
)

// APIError represents a structured error from the Passbolt API response.
// It carries the HTTP status code, server message, and response body,
// allowing consumers to inspect error details programmatically via errors.As.
type APIError struct {
	StatusCode int
	Message    string
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (code %d): %s", e.StatusCode, e.Message)
}

// Is supports backward compatibility with the deprecated sentinel errors.
// errors.Is(err, ErrAPIResponseErrorStatusCode) continues to work when err is an *APIError.
func (e *APIError) Is(target error) bool {
	if target == ErrAPIResponseErrorStatusCode {
		return true
	}
	if target == ErrAPIResponseUnknownStatusCode {
		return true
	}
	return false
}
