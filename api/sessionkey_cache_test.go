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
	if client.GetSessionKey(keyID) != nil {
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
	if client.GetSessionKey(keyID) == nil {
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
	if client.GetSessionKey(keyID) == nil {
		t.Error("Expected session key to be cached")
	}

	// Clear and verify
	client.ClearSessionKeyCache()
	if client.GetSessionKey(keyID) != nil {
		t.Error("Expected cache to be cleared")
	}

	// Logout clears cache
	client.DecryptMetadataWithKeyID(keyID, metadataKey, encrypted)
	client.Logout(ctx)
	if client.GetSessionKey(keyID) != nil {
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
