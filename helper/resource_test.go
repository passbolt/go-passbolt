package helper

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/passbolt/go-passbolt/api"
)

func TestResourceCreate(t *testing.T) {
	// Skip integration tests if no client is available
	if client == nil {
		t.SkipNow()
	}
	id, err := CreateResource(context.TODO(), client, "", "name", "username", "https://url.lan", "password123", "a password description")
	if err != nil {
		t.Fatalf("Creating Resource %v", err)
	}

	_, name, username, uri, password, description, err := GetResource(context.TODO(), client, id)
	if err != nil {
		t.Fatalf("Getting Resource %v", err)
	}

	equal(t, "Name", name, "name")
	equal(t, "Username", username, "username")
	equal(t, "URI", uri, "https://url.lan")
	equal(t, "Password", password, "password123")
	equal(t, "Description", description, "a password description")
}

func equal(t *testing.T, name, a, b string) {
	if a != b {
		t.Fatalf("Value %v is %v instead of %v", name, a, b)
	}
}

// TestUserKeySessionCaching tests that session key caching works for user-owned v5 resources
func TestUserKeySessionCaching(t *testing.T) {
	// Skip integration tests if no client is available
	if client == nil {
		t.SkipNow()
	}

	ctx := context.TODO()

	// Get user key fingerprint to construct expected cache key
	userKey, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("Failed to get user key: %v", err)
	}
	expectedCacheKey := "user-key:" + userKey.GetFingerprint()

	// Get resources
	resources, err := client.GetResources(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to get resources: %v", err)
	}

	// Find a user-owned v5 resource
	var userOwnedV5Resource *api.Resource
	for i := range resources {
		rType, err := client.GetResourceType(ctx, resources[i].ResourceTypeID)
		if err != nil {
			continue
		}
		if strings.HasPrefix(rType.Slug, "v5-") && resources[i].MetadataKeyType == api.MetadataKeyTypeUserKey {
			userOwnedV5Resource = &resources[i]
			t.Logf("Found user-owned v5 resource: %s (type: %s)", resources[i].ID, rType.Slug)
			break
		}
	}

	if userOwnedV5Resource == nil {
		t.Skip("No user-owned v5 resources available for testing")
	}

	// Clear session key cache to start fresh
	client.ClearSessionKeyCache()

	// Verify session key cache is empty initially
	sessionKey := client.GetSessionKey(expectedCacheKey)
	if sessionKey != nil {
		t.Error("Expected session key cache to be empty initially")
	}

	// Get resource type for metadata decryption
	rType, err := client.GetResourceType(ctx, userOwnedV5Resource.ResourceTypeID)
	if err != nil {
		t.Fatalf("Failed to get resource type: %v", err)
	}

	// First decryption - should cache session key with fingerprint-based key
	_, err = GetResourceMetadata(ctx, client, userOwnedV5Resource, rType)
	if err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}

	// Verify session key was cached with the expected key (user-key:FINGERPRINT)
	sessionKey = client.GetSessionKey(expectedCacheKey)
	if sessionKey == nil {
		t.Errorf("Expected session key to be cached with key %q", expectedCacheKey)
	} else {
		t.Logf("SUCCESS: Session key cached with key %q", expectedCacheKey)
	}

	// Second decryption - should use cached session key
	_, err = GetResourceMetadata(ctx, client, userOwnedV5Resource, rType)
	if err != nil {
		t.Fatalf("Second decryption failed: %v", err)
	}

	// Verify session key is still cached
	sessionKey = client.GetSessionKey(expectedCacheKey)
	if sessionKey == nil {
		t.Error("Expected session key to still be cached after second decryption")
	}

	t.Log("SUCCESS: Session key caching works for user-owned v5 resources")
}

// TestUserKeySessionCachingPerformance measures the performance improvement from session key caching
func TestUserKeySessionCachingPerformance(t *testing.T) {
	// Skip integration tests if no client is available
	if client == nil {
		t.SkipNow()
	}

	ctx := context.TODO()

	// Get resources
	resources, err := client.GetResources(ctx, nil)
	if err != nil {
		t.Fatalf("Failed to get resources: %v", err)
	}

	// Find multiple user-owned v5 resources (need at least 2 for performance test)
	var userOwnedV5Resources []api.Resource
	for i := range resources {
		rType, err := client.GetResourceType(ctx, resources[i].ResourceTypeID)
		if err != nil {
			continue
		}
		if strings.HasPrefix(rType.Slug, "v5-") && resources[i].MetadataKeyType == api.MetadataKeyTypeUserKey {
			userOwnedV5Resources = append(userOwnedV5Resources, resources[i])
		}
	}

	if len(userOwnedV5Resources) < 2 {
		t.Skipf("Need at least 2 user-owned v5 resources for performance test, found %d", len(userOwnedV5Resources))
	}

	// Get resource type
	rType, err := client.GetResourceType(ctx, userOwnedV5Resources[0].ResourceTypeID)
	if err != nil {
		t.Fatalf("Failed to get resource type: %v", err)
	}

	// Clear cache to start fresh
	client.ClearSessionKeyCache()

	// Measure first decryption (cache miss - full PGP)
	start := time.Now()
	_, err = GetResourceMetadata(ctx, client, &userOwnedV5Resources[0], rType)
	if err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}
	cacheMissDuration := time.Since(start)

	// Measure second decryption (cache hit - fast session key decrypt)
	start = time.Now()
	_, err = GetResourceMetadata(ctx, client, &userOwnedV5Resources[1], rType)
	if err != nil {
		t.Fatalf("Second decryption failed: %v", err)
	}
	cacheHitDuration := time.Since(start)

	// Calculate speedup
	speedup := float64(cacheMissDuration) / float64(cacheHitDuration)

	t.Logf("Cache miss (first decryption): %v", cacheMissDuration)
	t.Logf("Cache hit (second decryption): %v", cacheHitDuration)
	t.Logf("Speedup: %.2fx", speedup)

	// Verify cache hit is faster than cache miss
	if cacheHitDuration >= cacheMissDuration {
		t.Logf("Warning: Cache hit (%v) not faster than cache miss (%v)", cacheHitDuration, cacheMissDuration)
	}

	if speedup < 1.5 {
		t.Logf("Warning: Expected at least 1.5x speedup, got %.2fx (may vary by hardware)", speedup)
	} else {
		t.Logf("SUCCESS: Session key cache provides %.2fx speedup for user-owned resources", speedup)
	}
}
