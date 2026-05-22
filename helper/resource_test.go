package helper

import (
	"context"
	"strings"
	"testing"

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

	// Verify session key cache is empty initially (session keys are cached by resource ID)
	sessionKey := client.GetSessionKeyByResourceID(userOwnedV5Resource.ID)
	if sessionKey != nil {
		t.Error("Expected session key cache to be empty initially")
	}

	// Get resource type for metadata decryption
	rType, err := client.GetResourceType(ctx, userOwnedV5Resource.ResourceTypeID)
	if err != nil {
		t.Fatalf("Failed to get resource type: %v", err)
	}

	// First decryption - should cache session key by resource ID
	_, err = GetResourceMetadata(ctx, client, userOwnedV5Resource, rType)
	if err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}

	// Verify session key was cached by resource ID
	sessionKey = client.GetSessionKeyByResourceID(userOwnedV5Resource.ID)
	if sessionKey == nil {
		t.Errorf("Expected session key to be cached for resource %q", userOwnedV5Resource.ID)
	} else {
		t.Logf("SUCCESS: Session key cached for resource %q", userOwnedV5Resource.ID)
	}

	// Second decryption - should use cached session key
	_, err = GetResourceMetadata(ctx, client, userOwnedV5Resource, rType)
	if err != nil {
		t.Fatalf("Second decryption failed: %v", err)
	}

	// Verify session key is still cached
	sessionKey = client.GetSessionKeyByResourceID(userOwnedV5Resource.ID)
	if sessionKey == nil {
		t.Error("Expected session key to still be cached after second decryption")
	}

	t.Log("SUCCESS: Session key caching works for user-owned v5 resources")
}
