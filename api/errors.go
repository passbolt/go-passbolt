package api

import "errors"

var (
	// API Error Codes
	ErrAPIResponseErrorStatusCode   = errors.New("error API JSON Response Status")
	ErrAPIResponseUnknownStatusCode = errors.New("unknown API JSON Response Status")
)
