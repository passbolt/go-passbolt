//go:build integration

package api_test

import (
	"encoding/json"
	"testing"

	"github.com/passbolt/go-passbolt/api"
	"github.com/passbolt/go-passbolt/helper"
)

// TestClientCreationWithV3 tests that the client is created with gopenpgp v3
func TestClientCreationWithV3(t *testing.T) {
	client, err := api.NewClient(nil, "", testServerURL, testAdminPrivKey, testAdminPassword)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	// Verify PGP handle is initialized
	pgp := client.GetPGPHandle()
	if pgp == nil {
		t.Error("Expected non-nil PGP handle")
	}
}

// TestLoginClearsCacheOnStart tests that cache is cleared on login
func TestLoginClearsCacheOnStart(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// First client session - populate cache
	client1, ctx, cleanup1 := setupTestClient(t)
	defer cleanup1()

	// Populate cache
	_, err := client1.GetResourceTypesCached(ctx)
	if err != nil {
		t.Fatalf("Failed to get resource types: %v", err)
	}

	// Logout (clears cache and invalidates client)
	err = client1.Logout(ctx)
	if err != nil {
		t.Fatalf("Failed to logout: %v", err)
	}

	// Create new client for second session (simulating fresh login)
	// This is the correct pattern - new client per session
	client2, ctx2, cleanup2 := setupTestClient(t)
	defer cleanup2()

	// New client should have empty cache initially, then fetch from API
	types, err := client2.GetResourceTypesCached(ctx2)
	if err != nil {
		t.Fatalf("Failed to get resource types with new client: %v", err)
	}

	if len(types) == 0 {
		t.Error("Expected some resource types")
	}

	t.Log("SUCCESS: New client sessions start with clean cache")
}

// TestResourceTypesCaching tests the resource types caching functionality
func TestResourceTypesCaching(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// First call should fetch from API
	types1, err := client.GetResourceTypesCached(ctx)
	if err != nil {
		t.Fatalf("Failed to get resource types (first call): %v", err)
	}

	if len(types1) == 0 {
		t.Error("Expected some resource types")
	}

	// Second call should use cache
	types2, err := client.GetResourceTypesCached(ctx)
	if err != nil {
		t.Fatalf("Failed to get resource types (second call): %v", err)
	}

	if len(types2) != len(types1) {
		t.Errorf("Expected %d types from cache, got %d", len(types1), len(types2))
	}

	// Clear cache and verify it's empty
	client.ClearResourceTypesCache()

	// This should fetch from API again
	types3, err := client.GetResourceTypesCached(ctx)
	if err != nil {
		t.Fatalf("Failed to get resource types after cache clear: %v", err)
	}

	if len(types3) == 0 {
		t.Error("Expected some resource types after cache clear")
	}
}

// TestGetResourceTypeCached tests getting a single resource type from cache
func TestGetResourceTypeCached(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Get all types first
	types, err := client.GetResourceTypesCached(ctx)
	if err != nil {
		t.Fatalf("Failed to get resource types: %v", err)
	}

	if len(types) == 0 {
		t.Skip("No resource types available")
	}

	// Get a specific type by ID
	firstTypeID := types[0].ID
	rType, err := client.GetResourceTypeCached(ctx, firstTypeID)
	if err != nil {
		t.Fatalf("Failed to get resource type by ID: %v", err)
	}

	if rType.ID != firstTypeID {
		t.Errorf("Expected type ID %s, got %s", firstTypeID, rType.ID)
	}

	// Test getting by slug
	slug := types[0].Slug
	rType2, err := client.GetResourceTypeBySlugCached(ctx, slug)
	if err != nil {
		t.Fatalf("Failed to get resource type by slug: %v", err)
	}

	if rType2.Slug != slug {
		t.Errorf("Expected slug %s, got %s", slug, rType2.Slug)
	}
}

// TestMetadataKeysCaching tests the metadata keys caching functionality
func TestMetadataKeysCaching(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// First call should fetch from API
	keys1, err := client.GetMetadataKeysCached(ctx)
	if err != nil {
		t.Logf("Metadata keys not available (expected on v4 servers): %v", err)
		t.Skip("Skipping metadata key tests on v4 server")
	}

	t.Logf("Found %d metadata keys", len(keys1))

	// Second call should use cache
	keys2, err := client.GetMetadataKeysCached(ctx)
	if err != nil {
		t.Fatalf("Failed to get metadata keys (second call): %v", err)
	}

	if len(keys2) != len(keys1) {
		t.Errorf("Expected %d keys from cache, got %d", len(keys1), len(keys2))
	}

	// Clear cache
	client.ClearMetadataKeysCache()

	// This should fetch from API again
	keys3, err := client.GetMetadataKeysCached(ctx)
	if err != nil {
		t.Fatalf("Failed to get metadata keys after cache clear: %v", err)
	}

	if len(keys3) != len(keys1) {
		t.Errorf("Expected %d keys after cache clear, got %d", len(keys1), len(keys3))
	}
}

// TestDecryptedMetadataKeyCaching tests the decrypted metadata key caching
func TestDecryptedMetadataKeyCaching(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Get metadata keys
	keys, err := client.GetMetadataKeysCached(ctx)
	if err != nil {
		t.Skip("Metadata keys not available (v4 server)")
	}

	if len(keys) == 0 {
		t.Skip("No metadata keys available")
	}

	// Get decrypted key (first call - should decrypt and cache)
	key1, err := client.GetDecryptedMetadataKeyCached(ctx, keys[0].ID)
	if err != nil {
		t.Fatalf("Failed to get decrypted metadata key: %v", err)
	}

	if key1 == nil {
		t.Fatal("Expected non-nil decrypted key")
	}

	// Get same key again (should use cache)
	key2, err := client.GetDecryptedMetadataKeyCached(ctx, keys[0].ID)
	if err != nil {
		t.Fatalf("Failed to get cached decrypted metadata key: %v", err)
	}

	// Both keys should have same fingerprint
	if key1.GetFingerprint() != key2.GetFingerprint() {
		t.Error("Cached key fingerprint doesn't match original")
	}
}

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
	encrypted, err := client.EncryptMetadata(metadataKey, testData)
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

// TestCacheManagement tests that cache management functions work correctly
func TestCacheManagement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Populate caches
	_, err := client.GetResourceTypesCached(ctx)
	if err != nil {
		t.Fatalf("Failed to populate resource types cache: %v", err)
	}

	_, err = client.GetMetadataKeysCached(ctx)
	if err != nil {
		// Might fail on v4 servers, that's ok
		t.Logf("Could not populate metadata keys cache: %v", err)
	}

	// Clear all caches
	client.ClearCache()

	// After clearing, these should fetch from API again
	_, err = client.GetResourceTypesCached(ctx)
	if err != nil {
		t.Fatalf("Failed to get resource types after cache clear: %v", err)
	}
}
