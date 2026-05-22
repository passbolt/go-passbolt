package api

import "testing"

// TestClearMetadataKeysCache_PreservesEmptyMap verifies a subtle but
// load-bearing invariant: the cache must be reset to an EMPTY MAP,
// not nil. The production code adds to this map without nil-checking,
// so a regression that left the map at nil would crash on the next
// decryption attempt rather than just missing the cache.
func TestClearMetadataKeysCache_PreservesEmptyMap(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t)
	client.metadataKeysCache = []MetadataKey{{ID: validUUID}}

	client.ClearMetadataKeysCache()

	if client.metadataKeysCache != nil {
		t.Errorf("metadataKeysCache should be nil after Clear, got %+v", client.metadataKeysCache)
	}
	if client.decryptedMetadataKeysCache == nil {
		t.Fatal("decryptedMetadataKeysCache must be re-initialized to empty map, not left nil")
	}
	if len(client.decryptedMetadataKeysCache) != 0 {
		t.Errorf("decryptedMetadataKeysCache has %d entries, want 0", len(client.decryptedMetadataKeysCache))
	}
}

// TestClearCache_TouchesAllThreeCaches confirms ClearCache is a true
// composite operation: missing a delegate call would leave stale data
// across login sessions. The function is a 3-line dispatch, and
// dropping any of those lines is the kind of bug a refactor could
// introduce without obvious side effects in normal use.
func TestClearCache_TouchesAllThreeCaches(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t)
	client.resourceTypesCache = []ResourceType{{ID: validUUID}}
	client.metadataKeysCache = []MetadataKey{{ID: validUUID}}
	client.SetSessionKeyByMetadataKeyID("mk-1", sessionKeyForTest())

	client.ClearCache()

	if client.resourceTypesCache != nil {
		t.Error("resourceTypesCache not cleared")
	}
	if client.metadataKeysCache != nil {
		t.Error("metadataKeysCache not cleared")
	}
	if client.GetSessionKeyByMetadataKeyID("mk-1") != nil {
		t.Error("sessionKeyCache not cleared")
	}
}
