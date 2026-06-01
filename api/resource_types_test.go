package api

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
)

// ResourceType tests focus on the parts with real branching logic:
// the cache (verified by counting server hits), the
// IsSecretString/HasSecretField/HasMetadataField helpers (which parse
// a JSON schema and branch on its shape), and the parseSchema
// workarounds for broken Passbolt server versions. The trivial
// "decode list of types" and IsV5 prefix-check tests are intentionally
// omitted — they tested wiring, not behavior.

// TestGetResourceTypesCached_OnlyHitsServerOnce counts server-side
// hits across three lookups. The first call populates the cache; the
// next two must serve from memory. A regression that drops the cache
// (e.g. a refactor that returns the slice without storing it) would
// surface as calls != 1.
func TestGetResourceTypesCached_OnlyHitsServerOnce(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	_, client := newTestClient(t, route{
		method: "GET", path: "/resource-types.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			writeAPIResponse(t, w, []ResourceType{{ID: validUUID, Slug: "v5-default"}})
		},
	})

	for i := 0; i < 3; i++ {
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

// IsSecretString discriminates between string-shaped secrets (the
// legacy password type stores a single string) and structured ones
// (v5 stores a JSON object). HasSecretField relies on this; getting
// the dispatch wrong would break secret-field lookups in helper/.
func TestResourceType_IsSecretString(t *testing.T) {
	t.Parallel()

	stringDef := json.RawMessage(`{"resource":{"type":"object"},"secret":{"type":"string"}}`)
	objectDef := json.RawMessage(`{"resource":{"type":"object"},"secret":{"type":"object"}}`)

	if !(&ResourceType{Definition: stringDef}).IsSecretString() {
		t.Error("IsSecretString on string secret = false, want true")
	}
	if (&ResourceType{Definition: objectDef}).IsSecretString() {
		t.Error("IsSecretString on object secret = true, want false")
	}
}

// HasSecretField is the field-presence check used by helper/ to
// decide whether a resource carries a TOTP, a password, etc. Tests
// the present and absent cases.
func TestResourceType_HasSecretField(t *testing.T) {
	t.Parallel()

	def := json.RawMessage(`{
		"resource":{"type":"object","properties":{"name":{}}},
		"secret":{"type":"object","properties":{"password":{},"totp":{}}}
	}`)
	rt := &ResourceType{Definition: def}
	if !rt.HasSecretField("password") {
		t.Error("HasSecretField(password) = false, want true")
	}
	if rt.HasSecretField("nonexistent") {
		t.Error("HasSecretField(nonexistent) = true, want false")
	}
}

// HasMetadataField is the metadata-side counterpart to HasSecretField.
// Tested with both the present and absent cases to lock in the
// false-on-missing contract.
func TestResourceType_HasMetadataField(t *testing.T) {
	t.Parallel()

	def := json.RawMessage(`{
		"resource":{"type":"object","properties":{"name":{},"uri":{}}},
		"secret":{"type":"object"}
	}`)
	rt := &ResourceType{Definition: def}
	if !rt.HasMetadataField("name") {
		t.Error("HasMetadataField(name) = false, want true")
	}
	if rt.HasMetadataField("nonexistent") {
		t.Error("HasMetadataField(nonexistent) = true, want false")
	}
}

// TestResourceType_ParseSchema_FallbackForBrokenServer covers the
// real-world workaround for Passbolt 5.0, where some servers return
// the definition as the literal string "[]". The SDK substitutes a
// known-good schema from ResourceSchemas; without this fallback,
// every v5 metadata operation would fail on those servers.
func TestResourceType_ParseSchema_FallbackForBrokenServer(t *testing.T) {
	t.Parallel()

	rt := &ResourceType{
		Slug:       "v5-default",
		Definition: json.RawMessage(`[]`),
	}
	if !rt.HasMetadataField("name") {
		t.Error("fallback schema for v5-default should have a 'name' metadata field")
	}
}

// Counterpart to the previous test: if the broken slug isn't one we
// know about, we must NOT fabricate fields — better to return false
// than invent metadata.
func TestResourceType_ParseSchema_FallbackForUnknownSlugReturnsFalse(t *testing.T) {
	t.Parallel()

	rt := &ResourceType{
		Slug:       "unknown-slug",
		Definition: json.RawMessage(`[]`),
	}
	if rt.HasMetadataField("name") {
		t.Error("HasMetadataField should be false when no fallback schema exists")
	}
	if rt.IsSecretString() {
		t.Error("IsSecretString should be false when no fallback schema exists")
	}
}

// Some Passbolt builds double-encode the schema (JSON string
// containing JSON). parseSchema retries with Unmarshal-then-Unmarshal.
// Without this workaround, every helper that inspects the schema
// would fail silently on those servers.
func TestResourceType_ParseSchema_DoubleEncodedString(t *testing.T) {
	t.Parallel()

	rt := &ResourceType{
		Definition: json.RawMessage(`"{\"resource\":{\"type\":\"object\",\"properties\":{\"name\":{}}},\"secret\":{\"type\":\"object\"}}"`),
	}
	if !rt.HasMetadataField("name") {
		t.Error("HasMetadataField(name) = false, want true via string-unwrap workaround")
	}
}
