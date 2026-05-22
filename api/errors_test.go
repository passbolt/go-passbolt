package api

import (
	"errors"
	"strings"
	"testing"
)

// APIError tests cover the public error contract: the Error() string
// format (which is logged and shown to end-users) and the Is()
// backward-compat implementation that lets existing code using the
// deprecated sentinels keep working.

// TestAPIError_Error_FormatsCodeAndMessage pins the human-readable
// format. The CLI shows this string directly to users; a regression
// that hid the status code would force users to dig into wrapped
// error chains to triage problems.
func TestAPIError_Error_FormatsCodeAndMessage(t *testing.T) {
	t.Parallel()

	err := &APIError{StatusCode: 403, Message: "forbidden", Body: "{}"}
	s := err.Error()
	if !strings.Contains(s, "403") || !strings.Contains(s, "forbidden") {
		t.Errorf("Error() = %q, want it to contain 403 and forbidden", s)
	}
}

// TestAPIError_Is_BackwardCompat is the load-bearing test for the
// deprecation strategy. Old consumer code uses
// errors.Is(err, ErrAPIResponseErrorStatusCode); switching the SDK
// internals to *APIError without supporting the legacy sentinel would
// silently break those consumers. Conversely, Is() must NOT match
// unrelated sentinels.
func TestAPIError_Is_BackwardCompat(t *testing.T) {
	t.Parallel()

	err := &APIError{StatusCode: 500, Message: "boom"}
	if !errors.Is(err, ErrAPIResponseErrorStatusCode) {
		t.Error("errors.Is should match deprecated ErrAPIResponseErrorStatusCode")
	}
	if !errors.Is(err, ErrAPIResponseUnknownStatusCode) {
		t.Error("errors.Is should match deprecated ErrAPIResponseUnknownStatusCode")
	}
	if errors.Is(err, ErrInvalidUUID) {
		t.Error("errors.Is must not match unrelated sentinels (would mislead consumers branching on type)")
	}
}
