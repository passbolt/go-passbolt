//go:build integration

// Which resource types this build can actually use against a given Passbolt version.
//
// The bundle is authoritative, so a divergence from the server is a correctness bug that strict
// write validation turns into a user-visible failure, and the signal to tell users to update.
// Every advertised type is compared in full against the bundled schema.
//
// A type the server does not advertise is not a failure: the client refuses it up front
// (findResourceTypeBySlug) and reports that the API does not support it.
//
// On failure the server's definition is printed too, so refreshing a stale schema is a
// copy-paste, which is why the repository has no schema generator.

package api_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/passbolt/go-passbolt/api"
	"github.com/passbolt/go-passbolt/internal/testenv"
)

// maxDiffsPerSection caps reported differences so a wholesale upstream rewrite does not bury the
// summary in hundreds of lines.
const maxDiffsPerSection = 20

func TestEmbeddedSchemasMatchServerDefinitions(t *testing.T) {
	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	types, err := client.GetResourceTypes(ctx, nil)
	if err != nil {
		t.Fatalf("getting resource types: %v", err)
	}
	if len(types) == 0 {
		t.Fatal("server advertised no resource types")
	}

	advertised := make(map[string]bool, len(types))
	for _, rType := range types {
		advertised[rType.Slug] = true

		t.Run(rType.Slug, func(t *testing.T) {
			embedded, bundled := api.ResourceSchemas[rType.Slug]
			if !bundled {
				t.Errorf("server advertises resource type %q but this SDK bundles no schema for it, "+
					"so its resources cannot be read or written.\nfix: add api/schemas/%s.json with "+
					"the definition below\nserver definition:\n%s",
					rType.Slug, rType.Slug, prettyDefinition(rType.Definition))
				return
			}

			serverDef, err := parseServerDefinition(rType.Definition)
			if err != nil {
				// A definition of "[]" or absent is the broken-server case the bundle covers, so
				// there is nothing to compare against.
				t.Skipf("server sent no usable definition (%v); nothing to compare", err)
			}

			var bundledDef api.ResourceTypeSchema
			if err := json.Unmarshal(embedded, &bundledDef); err != nil {
				t.Fatalf("unmarshal bundled schema: %v", err)
			}

			for _, section := range []struct {
				name            string
				bundled, server map[string]any
			}{
				{"resource", bundledDef.Resource, serverDef.Resource},
				{"secret", bundledDef.Secret, serverDef.Secret},
			} {
				if diffs := schemaDiff("", section.bundled, section.server); len(diffs) > 0 {
					t.Errorf("%s %s: bundled schema differs from the server's definition:\n%s",
						rType.Slug, section.name, strings.Join(capDiffs(diffs), "\n"))
				}
			}

			if t.Failed() {
				t.Logf("fix: replace api/schemas/%s.json with the definition below "+
					"(image %s, resource type id %s)\nserver definition:\n%s",
					rType.Slug, testenv.PassboltImage(), rType.ID, prettyDefinition(rType.Definition))
			}
		})
	}

	// A slug we bundle that the server does not advertise is the sanctioned "client ahead of
	// server" case: findResourceTypeBySlug rejects it, so no user can reach it. Never a failure.
	var clientAhead []string
	for slug := range api.ResourceSchemas {
		if !advertised[slug] {
			clientAhead = append(clientAhead, slug)
		}
	}
	slices.Sort(clientAhead)
	if len(clientAhead) > 0 {
		t.Logf("bundled but not advertised by %s (client ahead of server, expected): %s",
			testenv.PassboltImage(), strings.Join(clientAhead, ", "))
	}
}

// parseServerDefinition decodes a server definition, retrying for the quirk where the schema
// arrives escaped as a JSON string. Nothing else reads Definition any more.
func parseServerDefinition(definition json.RawMessage) (*api.ResourceTypeSchema, error) {
	raw := strings.TrimSpace(string(definition))
	if raw == "" || raw == "[]" || raw == `"[]"` {
		return nil, fmt.Errorf("definition is %q", raw)
	}

	var schema api.ResourceTypeSchema
	if err := json.Unmarshal(definition, &schema); err != nil {
		var inner string
		if err2 := json.Unmarshal(definition, &inner); err2 == nil {
			if err3 := json.Unmarshal([]byte(inner), &schema); err3 == nil {
				return &schema, nil
			}
		}
		return nil, err
	}
	return &schema, nil
}

// schemaDiff walks two decoded schemas and returns a JSON-Pointer path per difference, so a
// failure names the exact keyword that drifted.
func schemaDiff(path string, embedded, server any) []string {
	switch e := embedded.(type) {
	case map[string]any:
		s, ok := server.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s: embedded is an object, server is %T", pathOrRoot(path), server)}
		}
		var diffs []string
		for _, key := range sortedKeys(e, s) {
			ev, inEmbedded := e[key]
			sv, inServer := s[key]
			switch {
			case !inServer:
				diffs = append(diffs, fmt.Sprintf("%s/%s: in embedded schema, absent from server", path, key))
			case !inEmbedded:
				diffs = append(diffs, fmt.Sprintf("%s/%s: absent from embedded schema, present on server", path, key))
			default:
				diffs = append(diffs, schemaDiff(path+"/"+key, ev, sv)...)
			}
		}
		return diffs

	case []any:
		s, ok := server.([]any)
		if !ok {
			return []string{fmt.Sprintf("%s: embedded is an array, server is %T", pathOrRoot(path), server)}
		}
		// "required" and "enum" are sets: PHP's json_encode ordering is not a contract, so
		// comparing positionally would report differences that do not exist.
		if isSetKeyword(path) {
			if a, b := toSortedStrings(e), toSortedStrings(s); !reflect.DeepEqual(a, b) {
				return []string{fmt.Sprintf("%s: embedded %v, server %v", pathOrRoot(path), a, b)}
			}
			return nil
		}
		if len(e) != len(s) {
			return []string{fmt.Sprintf("%s: embedded has %d items, server has %d", pathOrRoot(path), len(e), len(s))}
		}
		var diffs []string
		for i := range e {
			diffs = append(diffs, schemaDiff(fmt.Sprintf("%s/%d", path, i), e[i], s[i])...)
		}
		return diffs

	default:
		if !reflect.DeepEqual(embedded, server) {
			return []string{fmt.Sprintf("%s: embedded %v, server %v", pathOrRoot(path), embedded, server)}
		}
		return nil
	}
}

func isSetKeyword(path string) bool {
	return strings.HasSuffix(path, "/required") || strings.HasSuffix(path, "/enum")
}

func sortedKeys(sections ...map[string]any) []string {
	seen := map[string]bool{}
	for _, m := range sections {
		for k := range m {
			seen[k] = true
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

func toSortedStrings(values []any) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, fmt.Sprint(v))
	}
	slices.Sort(out)
	return out
}

func pathOrRoot(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func capDiffs(diffs []string) []string {
	if len(diffs) <= maxDiffsPerSection {
		return diffs
	}
	return append(diffs[:maxDiffsPerSection:maxDiffsPerSection],
		fmt.Sprintf("... (%d more differences)", len(diffs)-maxDiffsPerSection))
}

func prettyDefinition(definition json.RawMessage) string {
	schema, err := parseServerDefinition(definition)
	if err != nil {
		return string(definition)
	}
	out, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return string(definition)
	}
	return string(out)
}
