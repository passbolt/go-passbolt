package passbolt

import "errors"

var (
	ErrAPIResponseErrorStatusCode   = errors.New("Error API JSON Response Status")
	ErrAPIResponseUnknownStatusCode = errors.New("Unknown API JSON Response Status")
)
