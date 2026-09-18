package api

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
)

// ResourceType tests focus on the parts with real branching logic:
// the cache (verified by counting server hits) and the
// IsSecretString/HasSecretField/HasMetadataField helpers, which resolve
// the bundled schema and branch on its shape. They are driven by real
// bundled slugs rather than synthetic definitions, because Schema()
// resolves only from the embedded bundle. The trivial "decode list of
// types" and IsV5 prefix-check tests are intentionally omitted: they
// tested wiring, not behavior.

// TestGetResourceTypesCached_OnlyHitsServerOnce counts server-side
// hits across three lookups. The first call populates the cache; the
// next two must serve from memory. A regression that drops the cache
// (e.g. a refactor that returns the slice without storing it) would
// surface as calls != 1.
func TestGetResourceTypesCached_OnlyHitsServerOnce(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	client := newTestClient(t, route{
		method: "GET", path: "/resource-types.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			writeAPIResponse(t, w, []ResourceType{{ID: validUUID, Slug: "v5-default"}})
		},
	})

	for i := range 3 {
		types, err := client.GetResourceTypesCached(bg())
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if len(types) != 1 {
			t.Fatalf("call %d returned %d types, want 1", i, len(types))
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server received %d calls, want exactly 1 (cache should serve repeats)", got)
	}
}

// IsSecretString tells string-shaped secrets from JSON objects; HasSecretField relies on it.
func TestResourceType_IsSecretString(t *testing.T) {
	t.Parallel()

	for _, slug := range []string{"password-string", "v5-password-string"} {
		if !(&ResourceType{Slug: slug}).IsSecretString() {
			t.Errorf("IsSecretString(%s) = false, want true", slug)
		}
	}
	for _, slug := range []string{"v5-default", "password-and-description", "totp"} {
		if (&ResourceType{Slug: slug}).IsSecretString() {
			t.Errorf("IsSecretString(%s) = true, want false", slug)
		}
	}
}

// HasSecretField is the field-presence check used by helper/ to decide whether a resource
// carries a TOTP, a password, etc.
func TestResourceType_HasSecretField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		slug, field string
		want        bool
	}{
		{"v5-default", "password", true},
		{"v5-default", "totp", false},
		{"v5-default-with-totp", "totp", true},
		{"password-and-description", "description", true},
		{"totp", "totp", true},
		{"totp", "password", false},
		// A string secret has no fields at all, so the lookup short-circuits to false.
		{"v5-password-string", "password", false},
	}
	for _, tc := range tests {
		if got := (&ResourceType{Slug: tc.slug}).HasSecretField(tc.field); got != tc.want {
			t.Errorf("HasSecretField(%s, %s) = %v, want %v", tc.slug, tc.field, got, tc.want)
		}
	}
}

// HasMetadataField is the metadata-side counterpart. The uri/uris split is what
// helper.normalizeURIField dispatches on, so both spellings are pinned here.
func TestResourceType_HasMetadataField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		slug, field string
		want        bool
	}{
		{"v5-default", "name", true},
		{"v5-default", "uris", true},
		{"v5-default", "uri", false},
		{"password-and-description", "uri", true},
		{"password-and-description", "uris", false},
		{"v5-custom-fields", "custom_fields", true},
		{"v5-custom-fields", "username", false},
		{"v5-default", "nonexistent", false},
	}
	for _, tc := range tests {
		if got := (&ResourceType{Slug: tc.slug}).HasMetadataField(tc.field); got != tc.want {
			t.Errorf("HasMetadataField(%s, %s) = %v, want %v", tc.slug, tc.field, got, tc.want)
		}
	}
}

// A Passbolt 5.0 server returning the definition as the literal "[]" cannot affect anything,
// because the bundle is the only source.
func TestResourceType_BrokenServerDefinitionIrrelevant(t *testing.T) {
	t.Parallel()

	for _, def := range []string{`[]`, `"[]"`, ``} {
		rt := &ResourceType{Slug: "v5-default", Definition: json.RawMessage(def)}
		if !rt.HasMetadataField("name") {
			t.Errorf("Definition %q: v5-default should still resolve a 'name' metadata field", def)
		}
	}
}

// For an unbundled slug the predicates fail closed, even when the server sends a definition.
func TestResourceType_UnbundledSlugPredicatesReturnFalse(t *testing.T) {
	t.Parallel()

	validDefinition := json.RawMessage(`{"resource":{"type":"object","properties":{"name":{}}},"secret":{"type":"string"}}`)
	rt := &ResourceType{Slug: "unknown-slug", Definition: validDefinition}

	if rt.HasMetadataField("name") {
		t.Error("HasMetadataField should be false for an unbundled slug, even with a server definition")
	}
	if rt.HasSecretField("password") {
		t.Error("HasSecretField should be false for an unbundled slug, even with a server definition")
	}
	if rt.IsSecretString() {
		t.Error("IsSecretString should be false for an unbundled slug, even with a server definition")
	}
}
