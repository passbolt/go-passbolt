//go:build goexperiment.jsonv2 && go1.27

// This is the only test here that needs the new encoding/json implementation, and
// both halves of the constraint are load-bearing.
//
// goexperiment.jsonv2, because jsontext exists only when jsonv2 is enabled;
// otherwise json.RawMessage is a plain []byte with no IsValid method, so neither
// the import nor the call below would compile. That keeps the package building
// under GOEXPERIMENT=nojsonv2, the escape hatch back to the pre-1.27
// implementation.
//
// go1.27, because the SDK's go.mod declares 1.26.7 and a file's language version
// follows the module unless a //go:build go1.N constraint raises it. Without it,
// a 1.27 toolchain compiles this file - the experiment tag is on by default there
// - and then rejects jsontext.AllowDuplicateNames as too new for go1.26. It also
// excludes the file on a 1.26 toolchain, where the API is genuinely absent.
//
// Fold this into schema_test.go once the SDK floor reaches 1.27 and the opt-out
// is gone.

package api

import (
	"encoding/json/jsontext"
	"testing"
)

// TestResourceJsonSchemaNoDuplicateKeys guards the hand-written fallback schemas
// in schema.go against a duplicated object name.
//
// TestResourceJsonSchema cannot catch this: encoding/json keeps the last of a set
// of duplicate names without complaining, so a schema that accidentally defines
// "password" twice unmarshals cleanly with one definition silently discarded.
// Since Go 1.27 json.RawMessage is an alias for jsontext.Value, whose IsValid
// rejects duplicate names at any depth by default — exactly the check these blobs
// want, since they are edited by hand, run to several hundred lines, and only take
// effect against a broken v5.0 server, so a mistake would surface late and rarely.
func TestResourceJsonSchemaNoDuplicateKeys(t *testing.T) {
	for slug, schema := range ResourceSchemas {
		if schema.IsValid() {
			continue
		}
		// Narrow it down: valid once duplicates are permitted means the problem
		// is a duplicate name rather than a syntax error.
		if schema.IsValid(jsontext.AllowDuplicateNames(true)) {
			t.Errorf("Resource Schema %v contains a duplicate object name; one definition is being silently discarded", slug)
		} else {
			t.Errorf("Resource Schema %v is not valid JSON", slug)
		}
	}
}
