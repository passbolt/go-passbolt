package helper

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/passbolt/go-passbolt/api"
)

// Tests for the two pure routing functions in resource_create.go.
// Both transform a caller-supplied field map to match what the resource
// type's JSON schema actually expects. If they regressed, the
// CreateResource path would silently ship the wrong wire shape — the
// server would either reject it or (worse) accept a malformed
// payload that no client could read back coherently.
//
// We construct minimal ResourceType definitions per test so the
// HasMetadataField / HasSecretField lookups (api/resource_types.go)
// return exactly what we want for each branch.

// resourceType builds an api.ResourceType whose schema lists the given
// metadata and secret property names. This is the minimal shape that
// the schema-parsing helpers need.
func resourceType(slug string, metadataProps, secretProps []string) *api.ResourceType {
	props := func(names []string) map[string]any {
		out := make(map[string]any, len(names))
		for _, n := range names {
			out[n] = map[string]any{}
		}
		return out
	}
	def, _ := json.Marshal(map[string]any{
		"resource": map[string]any{"type": "object", "properties": props(metadataProps)},
		"secret":   map[string]any{"type": "object", "properties": props(secretProps)},
	})
	return &api.ResourceType{Slug: slug, Definition: def}
}

// TestRouteFieldBySchema_MovesFromMetadataToSecret covers the
// "description in v5-default" case: callers may put description in
// either map, and the function must move it to the secret side when
// the schema only declares it there. Without this, an inattentive
// caller would silently lose the description (it'd be sent unencrypted
// to a schema that doesn't accept it).
func TestRouteFieldBySchema_MovesFromMetadataToSecret(t *testing.T) {
	t.Parallel()

	rt := resourceType("v5-default",
		[]string{"name", "username"}, // metadata side: no "description"
		[]string{"password", "description"},
	)
	metadata := map[string]any{"name": "Stripe", "description": "prod creds"}
	secret := map[string]any{"password": "p"}

	routeFieldBySchema(rt, metadata, secret, "description")

	if _, stillThere := metadata["description"]; stillThere {
		t.Error("description should have been removed from metadata")
	}
	if got, ok := secret["description"].(string); !ok || got != "prod creds" {
		t.Errorf("secret[description] = %v, want %q", secret["description"], "prod creds")
	}
}

// TestRouteFieldBySchema_MovesFromSecretToMetadata covers the inverse
// case (e.g. "description" on v5-password-string lives in metadata,
// not in the secret). Symmetric to the previous test.
func TestRouteFieldBySchema_MovesFromSecretToMetadata(t *testing.T) {
	t.Parallel()

	rt := resourceType("v5-password-string",
		[]string{"name", "description"}, // metadata side: includes description
		[]string{"password"},            // secret side: does NOT
	)
	metadata := map[string]any{"name": "Stripe"}
	secret := map[string]any{"password": "p", "description": "prod creds"}

	routeFieldBySchema(rt, metadata, secret, "description")

	if _, stillThere := secret["description"]; stillThere {
		t.Error("description should have been removed from secret")
	}
	if got, ok := metadata["description"].(string); !ok || got != "prod creds" {
		t.Errorf("metadata[description] = %v, want %q", metadata["description"], "prod creds")
	}
}

// TestRouteFieldBySchema_NoOpWhenAlreadyOnCorrectSide ensures the
// function doesn't shuffle fields unnecessarily. A regression that
// duplicated the field on both sides would fail the
// validateCustomFields cross-field check at the next step.
func TestRouteFieldBySchema_NoOpWhenAlreadyOnCorrectSide(t *testing.T) {
	t.Parallel()

	rt := resourceType("v5-default",
		[]string{"name"},
		[]string{"password", "description"},
	)
	// description starts on the secret side, which matches the schema.
	metadata := map[string]any{"name": "x"}
	secret := map[string]any{"password": "p", "description": "d"}

	routeFieldBySchema(rt, metadata, secret, "description")

	if _, found := metadata["description"]; found {
		t.Error("description leaked into metadata; it was already correctly on the secret side")
	}
	if got, _ := secret["description"].(string); got != "d" {
		t.Errorf("secret[description] = %q, want %q", got, "d")
	}
}

// TestRouteFieldBySchema_NoOpWhenAbsent guards against a regression
// that wrote a zero value into the destination when the field was
// missing entirely.
func TestRouteFieldBySchema_NoOpWhenAbsent(t *testing.T) {
	t.Parallel()

	rt := resourceType("v5-default",
		[]string{"name"},
		[]string{"password", "description"},
	)
	metadata := map[string]any{"name": "x"}
	secret := map[string]any{"password": "p"}

	routeFieldBySchema(rt, metadata, secret, "description")

	if _, found := metadata["description"]; found {
		t.Error("metadata gained a description out of thin air")
	}
	if _, found := secret["description"]; found {
		t.Error("secret gained a description out of thin air")
	}
}

// TestNormalizeURIField_ConvertsUriStringToUrisArray is the V4→V5
// path: callers pass "uri" as a single string (the V4 convention) and
// the schema declares "uris" (the V5 convention). The function must
// convert without losing the value.
func TestNormalizeURIField_ConvertsUriStringToUrisArray(t *testing.T) {
	t.Parallel()

	rt := resourceType("v5-default",
		[]string{"name", "uris"}, // wants "uris", not "uri"
		[]string{"password"},
	)
	metadata := map[string]any{"name": "x", "uri": "https://stripe.com"}

	if err := normalizeURIField(rt, metadata); err != nil {
		t.Fatalf("normalizeURIField: %v", err)
	}

	if _, stillThere := metadata["uri"]; stillThere {
		t.Error("original \"uri\" key should have been deleted")
	}
	uris, ok := metadata["uris"].([]string)
	if !ok || len(uris) != 1 || uris[0] != "https://stripe.com" {
		t.Errorf("metadata[uris] = %+v, want [\"https://stripe.com\"]", metadata["uris"])
	}
}

// TestNormalizeURIField_ConvertsUrisStringSliceToUri is the V5→V4
// path with a strongly-typed []string input (callers building the
// metadata map programmatically).
func TestNormalizeURIField_ConvertsUrisStringSliceToUri(t *testing.T) {
	t.Parallel()

	rt := resourceType("password-and-description",
		[]string{"name", "uri"}, // wants "uri", not "uris"
		[]string{"password"},
	)
	metadata := map[string]any{"name": "x", "uris": []string{"https://stripe.com"}}

	if err := normalizeURIField(rt, metadata); err != nil {
		t.Fatalf("normalizeURIField: %v", err)
	}

	if _, stillThere := metadata["uris"]; stillThere {
		t.Error("original \"uris\" key should have been deleted")
	}
	if got, _ := metadata["uri"].(string); got != "https://stripe.com" {
		t.Errorf("metadata[uri] = %q, want %q", got, "https://stripe.com")
	}
}

// TestNormalizeURIField_ConvertsUrisAnySliceToUri covers the
// real-world input shape from json.Unmarshal: arrays come back as
// []any, not []string. A regression that handled only []string would
// silently drop URIs decoded from incoming JSON.
func TestNormalizeURIField_ConvertsUrisAnySliceToUri(t *testing.T) {
	t.Parallel()

	rt := resourceType("password-and-description",
		[]string{"name", "uri"},
		[]string{"password"},
	)
	metadata := map[string]any{"name": "x", "uris": []any{"https://stripe.com"}}

	if err := normalizeURIField(rt, metadata); err != nil {
		t.Fatalf("normalizeURIField: %v", err)
	}
	if got, _ := metadata["uri"].(string); got != "https://stripe.com" {
		t.Errorf("metadata[uri] = %q, want %q", got, "https://stripe.com")
	}
}

// TestNormalizeURIField_RejectsMultipleURIsForSingleURISchema is the
// defensive error path: a V4 schema declares a single "uri" field,
// but the caller passes a multi-URI list. Silently dropping all but
// the first would lose data; rejecting upfront forces the caller to
// reshape the call.
func TestNormalizeURIField_RejectsMultipleURIsForSingleURISchema(t *testing.T) {
	t.Parallel()

	rt := resourceType("password-and-description",
		[]string{"name", "uri"},
		[]string{"password"},
	)
	metadata := map[string]any{
		"name": "x",
		"uris": []string{"https://a.com", "https://b.com"},
	}

	err := normalizeURIField(rt, metadata)
	if err == nil {
		t.Fatal("expected error for multiple URIs with single-URI schema, got nil")
	}
	if !strings.Contains(err.Error(), "only supports a single URI") {
		t.Errorf("err %q should mention the single-URI constraint", err.Error())
	}
}

// TestNormalizeURIField_NoOpWhenFieldAlreadyMatchesSchema guards
// against unnecessary mutations: if the caller already passed the
// right shape, the function must leave the map alone.
func TestNormalizeURIField_NoOpWhenFieldAlreadyMatchesSchema(t *testing.T) {
	t.Parallel()

	rt := resourceType("v5-default",
		[]string{"name", "uris"},
		[]string{"password"},
	)
	metadata := map[string]any{"uris": []string{"https://x.test"}}

	if err := normalizeURIField(rt, metadata); err != nil {
		t.Fatalf("normalizeURIField: %v", err)
	}
	if _, sneakedIn := metadata["uri"]; sneakedIn {
		t.Error("uri leaked into metadata when uris was already correct")
	}
}
