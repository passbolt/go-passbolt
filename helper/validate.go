package helper

import (
	"errors"
	"fmt"
	"sync"

	"github.com/passbolt/go-passbolt/api"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
)

// validationMode selects how strictly a resource type's JSON schema is enforced.
type validationMode int

const (
	// validateRead is lenient: undeclared properties are accepted and left in the document, so
	// a resource written by a newer client stays readable.
	validateRead validationMode = iota
	// validateWrite is strict: undeclared top-level properties are rejected, so the SDK never
	// stores a field the resource type does not define. Used by create, update and share.
	validateWrite
)

// schemaSection selects one half of a resource type's schema.
type schemaSection int

const (
	schemaSectionResource schemaSection = iota
	schemaSectionSecret
)

// envelopeFields are the keys the SDK stamps on every v5 document it writes (see
// CreateResourceGeneric and UpdateResourceGeneric). No bundled "resource" schema declares them,
// and the "secret" schemas are inconsistent about object_type, so strict validation allows them
// explicitly. Without this every v5 write would be rejected.
var envelopeFields = map[schemaSection][]string{
	schemaSectionResource: {"object_type", "resource_type_id"},
	schemaSectionSecret:   {"object_type"},
}

// schemaCacheKey is slug-based, not ID-based: locally built types have no ID and would collide.
type schemaCacheKey struct {
	slug    string
	section schemaSection
	mode    validationMode
}

var (
	schemaCache   = make(map[schemaCacheKey]*jsonschema.Schema)
	schemaCacheMu sync.RWMutex
)

// compileSection compiles and caches one section of a type's schema in the given mode.
func compileSection(rType *api.ResourceType, section schemaSection, mode validationMode) (*jsonschema.Schema, error) {
	key := schemaCacheKey{slug: rType.Slug, section: section, mode: mode}

	schemaCacheMu.RLock()
	cached, ok := schemaCache[key]
	schemaCacheMu.RUnlock()
	if ok {
		return cached, nil
	}

	schemaCacheMu.Lock()
	defer schemaCacheMu.Unlock()
	// Another goroutine may have compiled the same section while we waited for the lock.
	if cached, ok := schemaCache[key]; ok {
		return cached, nil
	}
	schema, err := compileSectionUncached(rType, section, mode)
	if err != nil {
		return nil, err
	}
	schemaCache[key] = schema
	return schema, nil
}

func compileSectionUncached(rType *api.ResourceType, section schemaSection, mode validationMode) (*jsonschema.Schema, error) {
	// Schema returns a fresh copy, so the in-place mutation below never touches the bundle.
	def, err := rType.Schema()
	if err != nil {
		if errors.Is(err, api.ErrSchemaUnavailable) {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedResourceType, rType.Slug)
		}
		return nil, fmt.Errorf("resolving schema: %w", err)
	}

	node := def.Resource
	if section == schemaSectionSecret {
		node = def.Secret
	}

	// Strict mode rejects undeclared top-level fields; read stays permissive.
	if mode == validateWrite {
		api.DenyAdditionalProperties(node, envelopeFields[section]...)
	}

	// Format assertion stays off (the compiler default): Passbolt annotates custom field ids as
	// "uuid", and asserting it would reject documents the server accepts. validateCustomFields
	// enforces those ids instead.
	comp := jsonschema.NewCompiler()
	const urn = "urn:passbolt:schema"
	if err := comp.AddResource(urn, node); err != nil {
		return nil, fmt.Errorf("adding Json Schema: %w", err)
	}
	schema, err := comp.Compile(urn)
	if err != nil {
		return nil, fmt.Errorf("compiling Json Schema: %w", err)
	}
	return schema, nil
}

// wrapValidationError marks every failure with ErrSchemaValidation, and an undeclared-property
// failure additionally with ErrSchemaMismatch. Only strict mode denies undeclared properties, so
// lenient reads never carry ErrSchemaMismatch.
func wrapValidationError(what string, err error) error {
	if hasAdditionalPropertiesCause(err) {
		return fmt.Errorf("%w: validating %s with Schema: %w", ErrSchemaMismatch, what, err)
	}
	return fmt.Errorf("%w: validating %s with Schema: %w", ErrSchemaValidation, what, err)
}

// hasAdditionalPropertiesCause reports whether a jsonschema failure, or any nested cause, is an
// additionalProperties violation.
func hasAdditionalPropertiesCause(err error) bool {
	ve, ok := errors.AsType[*jsonschema.ValidationError](err)
	if !ok {
		return false
	}
	if _, ok := ve.ErrorKind.(*kind.AdditionalProperties); ok {
		return true
	}
	for _, cause := range ve.Causes {
		if hasAdditionalPropertiesCause(cause) {
			return true
		}
	}
	return false
}
