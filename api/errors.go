package api

import "errors"

var (
	// API Error Codes
	ErrAPIResponseErrorStatusCode   = errors.New("Error API JSON Response Status")
	ErrAPIResponseUnknownStatusCode = errors.New("Unknown API JSON Response Status")
)
