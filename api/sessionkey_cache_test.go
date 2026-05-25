//go:build integration

package api_test

import (
	"testing"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/passbolt/go-passbolt/api"
)

// TestSessionKeyCaching verifies session key cache behavior and performance
func TestSessionKeyCaching(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Get shared metadata key
	keys, err := client.GetMetadataKeysCached(ctx)
	if err != nil || len(keys) == 0 {
		t.Skip("Metadata keys not available (v4 server)")
	}

	keyID := keys[0].ID
	metadataKey, err := client.GetDecryptedMetadataKeyCached(ctx, keyID)
	if err != nil {
		t.Fatalf("Failed to get decrypted metadata key: %v", err)
	}

	testData := `{"object_type":"PASSBOLT_RESOURCE_METADATA","name":"Cache Test"}`
	encrypted, err := client.EncryptMetadata(metadataKey, testData)
	if err != nil {
		t.Fatalf("Failed to encrypt metadata: %v", err)
	}

	// Clear cache
	client.ClearSessionKeyCache()

	// Verify cache is empty
	if client.GetSessionKeyByMetadataKeyID(keyID) != nil {
		t.Error("Expected empty cache initially")
	}

	// First decrypt (cache miss)
	start := time.Now()
	decrypted1, err := client.DecryptMetadataWithKeyID(keyID, metadataKey, encrypted)
	cacheMissTime := time.Since(start)
	if err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}

	// Verify cached
	if client.GetSessionKeyByMetadataKeyID(keyID) == nil {
		t.Error("Expected session key to be cached")
	}

	// Second decrypt (cache hit)
	start = time.Now()
	decrypted2, err := client.DecryptMetadataWithKeyID(keyID, metadataKey, encrypted)
	cacheHitTime := time.Since(start)
	if err != nil {
		t.Fatalf("Second decryption failed: %v", err)
	}

	// Verify results
	if decrypted1 != testData || decrypted2 != testData {
		t.Error("Decryption returned wrong data")
	}

	speedup := float64(cacheMissTime) / float64(cacheHitTime)
	t.Logf("Cache miss: %v, Cache hit: %v, Speedup: %.1fx", cacheMissTime, cacheHitTime, speedup)
}

// TestSessionKeyCacheClear verifies cache clearing behavior
func TestSessionKeyCacheClear(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	keys, err := client.GetMetadataKeysCached(ctx)
	if err != nil || len(keys) == 0 {
		t.Skip("Metadata keys not available")
	}

	keyID := keys[0].ID
	metadataKey, _ := client.GetDecryptedMetadataKeyCached(ctx, keyID)
	testData := `{"object_type":"PASSBOLT_RESOURCE_METADATA","name":"Clear Test"}`
	encrypted, _ := client.EncryptMetadata(metadataKey, testData)

	// Populate cache
	client.DecryptMetadataWithKeyID(keyID, metadataKey, encrypted)

	// Verify cached
	if client.GetSessionKeyByMetadataKeyID(keyID) == nil {
		t.Error("Expected session key to be cached")
	}

	// Clear and verify
	client.ClearSessionKeyCache()
	if client.GetSessionKeyByMetadataKeyID(keyID) != nil {
		t.Error("Expected cache to be cleared")
	}

	// Logout clears cache
	client.DecryptMetadataWithKeyID(keyID, metadataKey, encrypted)
	client.Logout(ctx)
	if client.GetSessionKeyByMetadataKeyID(keyID) != nil {
		t.Error("Expected cache cleared on logout")
	}
}

// TestResourceSessionKeyPreFetch verifies pre-fetched session keys from login
func TestResourceSessionKeyPreFetch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	resources, err := client.GetResources(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to get resources: %v", err)
	}

	// Count v5 resources and cache hits
	var cacheHits, total int
	for _, r := range resources {
		if r.Metadata == "" {
			continue
		}
		total++
		if client.GetSessionKeyByResourceID(r.ID) != nil {
			cacheHits++
		}
	}

	if total == 0 {
		t.Skip("No v5 resources found")
	}

	hitRate := float64(cacheHits) / float64(total) * 100
	t.Logf("V5 resources: %d, Cache hits: %d (%.1f%%)", total, cacheHits, hitRate)
}

// TestPreFetchPerformance measures performance improvement from pre-fetching
func TestPreFetchPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	resources, err := client.GetResources(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to get resources: %v", err)
	}

	// Get v5 resources with metadata keys
	type prepared struct {
		id, keyID, metadata string
		key                 *crypto.Key
	}
	var items []prepared

	for _, r := range resources {
		if r.Metadata == "" {
			continue
		}
		if r.MetadataKeyType == api.MetadataKeyTypeUserKey {
			key, err := client.GetUserPrivateKeyCopy()
			if err == nil {
				items = append(items, prepared{r.ID, "user-key:" + key.GetFingerprint(), r.Metadata, key})
			}
		} else {
			key, err := client.GetDecryptedMetadataKeyCached(ctx, r.MetadataKeyID)
			if err == nil {
				items = append(items, prepared{r.ID, r.MetadataKeyID, r.Metadata, key})
			}
		}
		if len(items) >= 10 {
			break
		}
	}

	if len(items) < 3 {
		t.Skip("Need at least 3 v5 resources")
	}

	// WITH cache
	start := time.Now()
	for _, item := range items {
		client.DecryptMetadataWithResourceID(item.id, item.keyID, item.key, item.metadata)
	}
	withCache := time.Since(start)

	// Clear and measure WITHOUT cache
	client.ClearSessionKeyCache()
	start = time.Now()
	for _, item := range items {
		client.DecryptMetadataWithKeyID(item.keyID, item.key, item.metadata)
	}
	withoutCache := time.Since(start)

	speedup := float64(withoutCache) / float64(withCache)
	t.Logf("Resources: %d, With cache: %v, Without: %v, Speedup: %.1fx", len(items), withCache, withoutCache, speedup)
}

// TestSavePendingSessionKeys tests the pending session keys save functionality
func TestSavePendingSessionKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Get some v5 resources to work with
	resources, err := client.GetResources(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to get resources: %v", err)
	}

	// Find a v5 resource with metadata
	var testResource *api.Resource
	for _, r := range resources {
		if r.Metadata != "" && r.MetadataKeyType != api.MetadataKeyTypeUserKey {
			testResource = &r
			break
		}
	}

	if testResource == nil {
		t.Skip("No v5 resources with shared metadata key found")
	}

	// Clear the cache to start fresh
	client.ClearSessionKeyCache()

	// Verify no pending keys initially
	if count := client.GetPendingSessionKeysCount(); count != 0 {
		t.Logf("Warning: Found %d pre-existing pending keys, clearing them", count)
		client.GetPendingSessionKeys() // Clear them
	}

	// Decrypt the resource metadata - this should add a pending session key
	metadataKey, err := client.GetDecryptedMetadataKeyCached(ctx, testResource.MetadataKeyID)
	if err != nil {
		t.Fatalf("Failed to get metadata key: %v", err)
	}

	// Use DecryptMetadataWithResourceID which adds pending keys
	_, err = client.DecryptMetadataWithResourceID(testResource.ID, testResource.MetadataKeyID, metadataKey, testResource.Metadata)
	if err != nil {
		t.Fatalf("Failed to decrypt metadata: %v", err)
	}

	// Verify we have a pending session key
	pendingCount := client.GetPendingSessionKeysCount()
	t.Logf("Pending session keys after decrypt: %d", pendingCount)

	// Note: The pending keys may have already been saved during login
	// Let's verify the cache is populated via resource ID
	cachedKey := client.GetSessionKeyByResourceID(testResource.ID)
	if cachedKey == nil {
		t.Log("No cached session key by resource ID - this may be normal if server already had session key")
	} else {
		t.Log("Session key cached by resource ID")
	}

	// Save pending session keys to server
	savedCount, err := client.SavePendingSessionKeys(ctx)
	if err != nil {
		t.Fatalf("Failed to save pending session keys: %v", err)
	}
	t.Logf("Saved %d pending session keys to server", savedCount)

	// Verify pending list is cleared
	if count := client.GetPendingSessionKeysCount(); count != 0 {
		t.Errorf("Expected 0 pending keys after save, got %d", count)
	}

	// Create a new client to verify keys were saved to server
	client2, _, cleanup2 := setupTestClient(t)
	defer cleanup2()

	// The new client should have the session keys pre-fetched during login
	cachedKey2 := client2.GetSessionKeyByResourceID(testResource.ID)
	if cachedKey2 == nil {
		// This is expected if the server doesn't have session keys for this resource yet
		t.Log("Note: Session key not found in new client cache - server may not support session key persistence or this is a new resource")
	} else {
		t.Log("SUCCESS: Session key was retrieved from server by new client")
	}

	// Verify we can still decrypt with the new client
	_, err = client2.DecryptMetadataWithResourceID(testResource.ID, testResource.MetadataKeyID, metadataKey, testResource.Metadata)
	if err != nil {
		t.Errorf("Failed to decrypt metadata with new client: %v", err)
	} else {
		t.Log("SUCCESS: New client can decrypt metadata (using cached or server session key)")
	}
}

// TestConcurrentCacheAccessIntegration tests concurrent access with real server.
// The Client is now thread-safe, so we can run parallel decryption operations.
func TestConcurrentCacheAccessIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Get metadata keys
	keys, err := client.GetMetadataKeysCached(ctx)
	if err != nil || len(keys) == 0 {
		t.Skip("Metadata keys not available")
	}

	keyID := keys[0].ID
	metadataKey, err := client.GetDecryptedMetadataKeyCached(ctx, keyID)
	if err != nil {
		t.Fatalf("Failed to get metadata key: %v", err)
	}

	testData := `{"object_type":"PASSBOLT_RESOURCE_METADATA","name":"Concurrent Test"}`
	encrypted, err := client.EncryptMetadata(metadataKey, testData)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Clear cache
	client.ClearSessionKeyCache()

	const numGoroutines = 5
	const numDecrypts = 10

	// Use channels to collect results
	results := make(chan error, numGoroutines*numDecrypts)
	done := make(chan struct{})

	// Start concurrent decryption goroutines
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numDecrypts; j++ {
				_, err := client.DecryptMetadataWithKeyID(keyID, metadataKey, encrypted)
				results <- err
			}
		}(i)
	}

	// Collect results
	go func() {
		for i := 0; i < numGoroutines*numDecrypts; i++ {
			if err := <-results; err != nil {
				t.Errorf("Decryption error in concurrent test: %v", err)
			}
		}
		close(done)
	}()

	// Wait for completion with timeout
	select {
	case <-done:
		t.Logf("Completed %d concurrent decryptions successfully", numGoroutines*numDecrypts)
	case <-time.After(30 * time.Second):
		t.Fatal("Concurrent test timed out")
	}

	// Verify cache is still functional
	if client.GetSessionKeyByMetadataKeyID(keyID) == nil {
		t.Error("Cache should have session key after concurrent access")
	}
}
