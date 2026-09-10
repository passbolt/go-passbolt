package helper

import (
	"errors"
	"fmt"
	"sync"

	"github.com/passbolt/go-passbolt/api"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaCache caches compiled JSON schemas, keyed by (slug, section).
var (
	schemaCache   = make(map[string]*jsonschema.Schema)
	schemaCacheMu sync.RWMutex
)

const (
	schemaSectionResource = "resource"
	schemaSectionSecret   = "secret"
)

// compileSection compiles and caches one section ("resource" or "secret") of a type's schema.
// The key is slug-based, not ID-based: locally built types have no ID and would collide.
func compileSection(rType *api.ResourceType, section string) (*jsonschema.Schema, error) {
	cacheKey := rType.Slug + "|" + section

	schemaCacheMu.RLock()
	cached, ok := schemaCache[cacheKey]
	schemaCacheMu.RUnlock()
	if ok {
		return cached, nil
	}

	def, err := rType.Schema()
	if err != nil {
		if errors.Is(err, api.ErrSchemaUnavailable) {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedResourceType, rType.Slug)
		}
		return nil, fmt.Errorf("resolving schema: %w", err)
	}

	var node map[string]any
	switch section {
	case schemaSectionResource:
		node = def.Resource
	case schemaSectionSecret:
		node = def.Secret
	default:
		return nil, fmt.Errorf("unknown schema section %q", section)
	}

	// Format assertion stays off (the compiler default): Passbolt annotates custom field ids as
	// "uuid", and asserting it would reject documents the server accepts. validateCustomFields
	// enforces those ids instead.
	comp := jsonschema.NewCompiler()
	urn := "urn:passbolt:schema:" + section
	if err := comp.AddResource(urn, node); err != nil {
		return nil, fmt.Errorf("adding Json Schema: %w", err)
	}
	schema, err := comp.Compile(urn)
	if err != nil {
		return nil, fmt.Errorf("compiling Json Schema: %w", err)
	}

	schemaCacheMu.Lock()
	schemaCache[cacheKey] = schema
	schemaCacheMu.Unlock()
	return schema, nil
}
