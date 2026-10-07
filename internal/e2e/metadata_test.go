//go:build integration

package e2e

// V5 metadata encryption and decryption.

import (
	"encoding/json"
	"testing"

	"github.com/passbolt/go-passbolt/api"
	"github.com/passbolt/go-passbolt/helper"
)

// TestMetadataEncryptionDecryption tests metadata encryption and decryption
func TestMetadataEncryptionDecryption(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Get a metadata key
	keys, err := client.GetMetadataKeysCached(ctx)
	if err != nil {
		t.Skip("Metadata keys not available (v4 server)")
	}

	if len(keys) == 0 {
		t.Skip("No metadata keys available")
	}

	// Get decrypted metadata key
	metadataKey, err := client.GetDecryptedMetadataKeyCached(ctx, keys[0].ID)
	if err != nil {
		t.Fatalf("Failed to get decrypted metadata key: %v", err)
	}

	// Test data
	testData := `{"object_type":"PASSBOLT_RESOURCE_METADATA","name":"Test Resource","username":"testuser"}`

	// Encrypt
	encrypted, err := client.EncryptMetadataWithKeyType(metadataKey, api.MetadataKeyTypeUserKey, testData)
	if err != nil {
		t.Fatalf("Failed to encrypt metadata: %v", err)
	}

	if encrypted == testData {
		t.Error("Encrypted data should differ from plaintext")
	}

	// Decrypt
	decrypted, err := client.DecryptMetadata(metadataKey, encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt metadata: %v", err)
	}

	if decrypted != testData {
		t.Errorf("Decrypted data doesn't match original.\nExpected: %s\nGot: %s", testData, decrypted)
	}
}

// TestGetResourceWithMetadata tests the helper function for getting resource metadata
func TestGetResourceWithMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Create a v5 test resource with metadata
	resourceID, err := helper.CreateResourceGeneric(
		ctx,
		client,
		"v5-default",
		"", // no folder
		map[string]any{
			"name":     "Test Resource With Metadata",
			"username": "testuser",
			"uris":     []string{"https://test.example.com"},
		},
		map[string]any{
			"password":    "TestPassword123!",
			"description": "Test description for metadata test",
		},
	)
	if err != nil {
		t.Skipf("Cannot create v5 resource (server may not support v5): %v", err)
	}

	// Clean up the test resource when done
	defer func() {
		if err := client.DeleteResource(ctx, resourceID); err != nil {
			t.Logf("Warning: Failed to delete test resource %s: %v", resourceID, err)
		}
	}()

	// Get the created resource
	testResource, err := client.GetResource(ctx, resourceID)
	if err != nil {
		t.Fatalf("Failed to get created resource: %v", err)
	}

	// Verify it has metadata
	if testResource.Metadata == "" {
		t.Fatal("Created resource has no metadata")
	}

	// Get resource type
	rType, err := client.GetResourceTypeCached(ctx, testResource.ResourceTypeID)
	if err != nil {
		t.Fatalf("Failed to get resource type: %v", err)
	}

	// Get and decrypt metadata using helper
	metadata, err := helper.GetResourceMetadata(ctx, client, testResource, rType)
	if err != nil {
		t.Fatalf("Failed to get resource metadata: %v", err)
	}

	// Verify it's valid JSON
	var metadataObj map[string]interface{}
	err = json.Unmarshal([]byte(metadata), &metadataObj)
	if err != nil {
		t.Fatalf("Metadata is not valid JSON: %v", err)
	}

	// Verify it has expected fields
	objectType, ok := metadataObj["object_type"]
	if !ok {
		t.Error("Metadata missing object_type field")
	}

	if objectType != api.PassboltObjectTypeResourceMetadata {
		t.Errorf("Expected object_type %s, got %v", api.PassboltObjectTypeResourceMetadata, objectType)
	}

	// Verify the metadata contains the values we set
	if name, ok := metadataObj["name"].(string); ok {
		if name != "Test Resource With Metadata" {
			t.Errorf("Expected name 'Test Resource With Metadata', got %s", name)
		}
	} else {
		t.Error("Metadata missing name field")
	}

	if username, ok := metadataObj["username"].(string); ok {
		if username != "testuser" {
			t.Errorf("Expected username 'testuser', got %s", username)
		}
	} else {
		t.Error("Metadata missing username field")
	}
}
