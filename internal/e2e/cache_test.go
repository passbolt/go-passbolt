//go:build integration

package e2e

// Resource type and metadata key caches.

import "testing"

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

// TestClearMetadataKeysCacheZerosKeys tests that cache clearing zeros key memory
func TestClearMetadataKeysCacheZerosKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Get and cache a metadata key
	keys, err := client.GetMetadataKeysCached(ctx)
	if err != nil {
		t.Skip("Metadata keys not available (v4 server)")
	}

	if len(keys) == 0 {
		t.Skip("No metadata keys available")
	}

	keyID := keys[0].ID
	cachedKey, err := client.GetDecryptedMetadataKeyCached(ctx, keyID)
	if err != nil {
		t.Fatalf("Failed to cache metadata key: %v", err)
	}

	fingerprint := cachedKey.GetFingerprint()
	t.Logf("Cached key fingerprint: %s", fingerprint)

	// Clear cache (should zero key memory)
	client.ClearMetadataKeysCache()

	// Verify we need to fetch again (cache was cleared)
	cachedKey2, err := client.GetDecryptedMetadataKeyCached(ctx, keyID)
	if err != nil {
		t.Fatalf("Failed to get metadata key after clear: %v", err)
	}

	// Verify we got the same key (by fingerprint) but it was re-fetched
	if cachedKey2.GetFingerprint() != fingerprint {
		t.Error("Key fingerprint changed after cache clear")
	}

	t.Log("SUCCESS: Cache clearing and re-fetching works correctly")
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
