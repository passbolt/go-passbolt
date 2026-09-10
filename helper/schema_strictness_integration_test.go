//go:build integration

package helper

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/passbolt/go-passbolt/api"
)

// A stored v5 resource carrying an undeclared metadata property reads fine, but update and share
// fail with ErrSchemaMismatch. Only observable against a real server.
func TestSchemaStrictness_ReadLenientWriteStrict(t *testing.T) {
	ctx := context.Background()

	resourceID, err := CreateResourceGeneric(ctx, client, "v5-default", "",
		map[string]any{"name": "strictness-probe", "username": "u"},
		map[string]any{"password": "correct horse battery staple"},
	)
	if err != nil {
		t.Fatalf("creating probe resource: %v", err)
	}

	// Rewrite the stored metadata with an undeclared property, bypassing the SDK's validation
	// the way a newer client would.
	rType := storeRawMetadata(t, resourceID, map[string]any{
		"name":         "strictness-probe",
		"username":     "u",
		"future_field": "written by a newer client",
	})

	t.Run("read is lenient and non-mutating", func(t *testing.T) {
		resource, err := client.GetResource(ctx, resourceID)
		if err != nil {
			t.Fatalf("getting resource: %v", err)
		}
		secret, err := client.GetSecret(ctx, resourceID)
		if err != nil {
			t.Fatalf("getting secret: %v", err)
		}

		_, metaFields, _, err := GetResourceFieldMaps(client, *resource, *secret, *rType, true)
		if err != nil {
			t.Fatalf("GetResourceFieldMaps should tolerate an undeclared property: %v", err)
		}
		if got := metaFields["future_field"]; got != "written by a newer client" {
			t.Errorf("undeclared property was not preserved: future_field = %v", got)
		}
	})

	t.Run("update is strict", func(t *testing.T) {
		err := UpdateResourceGeneric(ctx, client, resourceID,
			map[string]any{"name": "renamed"}, map[string]any{})
		if !errors.Is(err, ErrSchemaMismatch) {
			t.Fatalf("expected ErrSchemaMismatch, got %v", err)
		}
		if !strings.Contains(err.Error(), "future_field") {
			t.Errorf("error should name the offending property, got %q", err.Error())
		}
	})

	t.Run("share is strict", func(t *testing.T) {
		user, err := pb.CreateUser(ctx, "schema-probe@passbolt.com", "Schema", "Probe", "user", "schema-probe@passbolt.com")
		if err != nil {
			t.Skipf("could not create a second user to share with: %v", err)
		}

		err = ShareResourceWithUsersAndGroups(ctx, client, resourceID, []string{user.UserID}, nil, 7)
		if !errors.Is(err, ErrSchemaMismatch) {
			t.Fatalf("expected ErrSchemaMismatch, got %v", err)
		}
	})
}

// A stored document that breaks a declared constraint is not readable, but the update that
// repairs it must go through: only the merged document is validated, not the merge base.
func TestUpdateResourceGeneric_RepairsInvalidStoredMetadata(t *testing.T) {
	ctx := context.Background()

	resourceID, err := CreateResourceGeneric(ctx, client, "v5-default", "",
		map[string]any{"name": "repair-probe", "username": "u"},
		map[string]any{"password": "correct horse battery staple"},
	)
	if err != nil {
		t.Fatalf("creating probe resource: %v", err)
	}
	t.Cleanup(func() { _ = DeleteResource(ctx, client, resourceID) })

	// v5-default caps name at 255 characters.
	rType := storeRawMetadata(t, resourceID, map[string]any{
		"name":     strings.Repeat("x", 300),
		"username": "u",
	})

	resource, err := client.GetResource(ctx, resourceID)
	if err != nil {
		t.Fatalf("getting resource: %v", err)
	}
	if _, err := GetResourceMetadata(ctx, client, resource, rType); !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("the broken document should fail lenient validation, got %v", err)
	}

	if err := UpdateResourceGeneric(ctx, client, resourceID, map[string]any{"name": "repaired"}, nil); err != nil {
		t.Fatalf("the repairing update should succeed, got %v", err)
	}

	_, name, _, _, _, _, err := GetResource(ctx, client, resourceID)
	if err != nil {
		t.Fatalf("reading back the repaired resource: %v", err)
	}
	if name != "repaired" {
		t.Errorf("name = %q, want %q", name, "repaired")
	}
}

// Update stamps the envelope itself, as create does, so a caller cannot store a bogus
// object_type or resource_type_id through the field maps.
func TestUpdateResourceGeneric_RestampsEnvelope(t *testing.T) {
	ctx := context.Background()

	resourceID, err := CreateResourceGeneric(ctx, client, "v5-default", "",
		map[string]any{"name": "envelope-probe", "username": "u"},
		map[string]any{"password": "correct horse battery staple"},
	)
	if err != nil {
		t.Fatalf("creating probe resource: %v", err)
	}
	t.Cleanup(func() { _ = DeleteResource(ctx, client, resourceID) })

	err = UpdateResourceGeneric(ctx, client, resourceID,
		map[string]any{"object_type": "garbage", "resource_type_id": "not-a-uuid"},
		map[string]any{"object_type": "garbage"},
	)
	if err != nil {
		t.Fatalf("update with a tampered envelope should still succeed: %v", err)
	}

	resource, err := client.GetResource(ctx, resourceID)
	if err != nil {
		t.Fatalf("getting resource: %v", err)
	}
	secret, err := client.GetSecret(ctx, resourceID)
	if err != nil {
		t.Fatalf("getting secret: %v", err)
	}
	rType, err := client.GetResourceType(ctx, resource.ResourceTypeID)
	if err != nil {
		t.Fatalf("getting resource type: %v", err)
	}
	_, metaFields, secretFields, err := GetResourceFieldMaps(client, *resource, *secret, *rType, true)
	if err != nil {
		t.Fatalf("GetResourceFieldMaps: %v", err)
	}
	if got := metaFields["object_type"]; got != api.PassboltObjectTypeResourceMetadata {
		t.Errorf("metadata object_type = %v, want %q", got, api.PassboltObjectTypeResourceMetadata)
	}
	if got := metaFields["resource_type_id"]; got != rType.ID {
		t.Errorf("metadata resource_type_id = %v, want %q", got, rType.ID)
	}
	if got := secretFields["object_type"]; got != api.PassboltObjectTypeSecretData {
		t.Errorf("secret object_type = %v, want %q", got, api.PassboltObjectTypeSecretData)
	}
}

// storeRawMetadata encrypts and stores metadata for a v5 resource without going through the
// SDK's validation, the way a newer or buggy client would. The envelope is filled in; the rest
// of the document is the caller's. It returns the resource's type for later reads.
func storeRawMetadata(t *testing.T, resourceID string, metadata map[string]any) *api.ResourceType {
	t.Helper()
	ctx := context.Background()

	resource, err := client.GetResource(ctx, resourceID)
	if err != nil {
		t.Fatalf("getting resource: %v", err)
	}
	rType, err := client.GetResourceType(ctx, resource.ResourceTypeID)
	if err != nil {
		t.Fatalf("getting resource type: %v", err)
	}

	metadata["object_type"] = api.PassboltObjectTypeResourceMetadata
	metadata["resource_type_id"] = rType.ID
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("marshaling metadata: %v", err)
	}

	personal := resource.MetadataKeyType != api.MetadataKeyTypeSharedKey
	keyID, keyType, publicKey, err := client.GetMetadataKey(ctx, personal)
	if err != nil {
		t.Fatalf("getting metadata key: %v", err)
	}
	encrypted, err := client.EncryptMetadataWithKeyType(publicKey, keyType, string(raw))
	if err != nil {
		t.Fatalf("encrypting metadata: %v", err)
	}
	if _, err := client.UpdateResource(ctx, resourceID, api.Resource{
		ID:              resourceID,
		ResourceTypeID:  resource.ResourceTypeID,
		Metadata:        encrypted,
		MetadataKeyID:   keyID,
		MetadataKeyType: keyType,
	}); err != nil {
		t.Fatalf("storing raw metadata: %v", err)
	}
	return rType
}
