package api

import (
	"context"
	"sync"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// ============================================================================
// Unit Tests for Cache Operations (No Server Required)
//
// These tests verify the cache infrastructure works correctly without
// requiring a Passbolt server connection. They test:
// - Secure zeroing of session keys
// - Cache key prefixes are used correctly
// - Thread safety of cache operations
// ============================================================================

// TestSecureZeroSessionKey verifies that session key bytes are properly zeroed
func TestSecureZeroSessionKey(t *testing.T) {
	tests := []struct {
		name       string
		sessionKey *crypto.SessionKey
		wantNilKey bool
	}{
		{
			name:       "nil session key",
			sessionKey: nil,
			wantNilKey: true,
		},
		{
			name:       "session key with nil bytes",
			sessionKey: &crypto.SessionKey{Key: nil, Algo: "aes256"},
			wantNilKey: true,
		},
		{
			name:       "session key with empty bytes",
			sessionKey: &crypto.SessionKey{Key: []byte{}, Algo: "aes256"},
			wantNilKey: true,
		},
		{
			name:       "session key with data",
			sessionKey: crypto.NewSessionKeyFromToken([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, "aes256"),
			wantNilKey: true,
		},
		{
			name:       "full AES-256 session key (32 bytes)",
			sessionKey: crypto.NewSessionKeyFromToken(make([]byte, 32), "aes256"),
			wantNilKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For non-nil keys with data, verify bytes are non-zero before zeroing
			if tt.sessionKey != nil && len(tt.sessionKey.Key) > 0 {
				// Fill with test data
				for i := range tt.sessionKey.Key {
					tt.sessionKey.Key[i] = byte(i + 1)
				}
			}

			// Call the secure zeroing function
			secureZeroSessionKey(tt.sessionKey)

			// Verify results
			if tt.sessionKey == nil {
				return // nil input is handled gracefully
			}

			if tt.wantNilKey && tt.sessionKey.Key != nil {
				t.Error("Expected Key to be nil after zeroing")
			}
		})
	}
}

// TestSecureZeroSessionKeyActuallyZerosBytes verifies bytes are zeroed before nil
func TestSecureZeroSessionKeyActuallyZerosBytes(t *testing.T) {
	// Create a session key with known data
	originalData := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	sessionKey := crypto.NewSessionKeyFromToken(originalData, "aes256")

	// Keep a reference to the underlying array
	keyRef := sessionKey.Key

	// Zero the session key
	secureZeroSessionKey(sessionKey)

	// The original slice should have been zeroed before being set to nil
	// Note: In Go, after setting slice to nil, we can't verify the original bytes
	// But we can verify the sessionKey.Key is nil
	if sessionKey.Key != nil {
		t.Error("Expected sessionKey.Key to be nil after zeroing")
	}

	// Verify the key reference still points to zeroed memory (if accessible)
	// This is a best-effort check - Go may have already cleaned up
	for i, b := range keyRef {
		if b != 0 {
			t.Errorf("Byte at index %d was not zeroed: got %#x, want 0x00", i, b)
		}
	}
}

// TestSessionKeyCachePrefixes verifies the correct prefixes are used for cache keys
func TestSessionKeyCachePrefixes(t *testing.T) {
	// Verify the constant values
	if sessionKeyCachePrefixResource != "resource:" {
		t.Errorf("sessionKeyCachePrefixResource = %q, want %q", sessionKeyCachePrefixResource, "resource:")
	}
	if sessionKeyCachePrefixMetaKey != "metakey:" {
		t.Errorf("sessionKeyCachePrefixMetaKey = %q, want %q", sessionKeyCachePrefixMetaKey, "metakey:")
	}
}

// TestSessionKeyCacheOperations tests cache get/set operations with correct prefixes
func TestSessionKeyCacheOperations(t *testing.T) {
	// Create a minimal client with just the cache fields initialized
	client := &Client{
		sessionKeyCache:    make(map[string]*crypto.SessionKey),
		pendingSessionKeys: make(map[string]*PendingSessionKey),
	}

	resourceID := "test-resource-uuid"
	metadataKeyID := "test-metadata-key-uuid"
	sessionKey := crypto.NewSessionKeyFromToken([]byte("test-session-key-bytes!!"), "aes256")

	// Test SetSessionKeyByResourceID and GetSessionKeyByResourceID
	t.Run("ResourceID cache operations", func(t *testing.T) {
		client.SetSessionKeyByResourceID(resourceID, sessionKey)

		retrieved := client.GetSessionKeyByResourceID(resourceID)
		if retrieved == nil {
			t.Fatal("GetSessionKeyByResourceID returned nil")
		}
		// Compare contents, not pointers (getters return clones)
		if retrieved.Algo != sessionKey.Algo || string(retrieved.Key) != string(sessionKey.Key) {
			t.Error("Retrieved session key contents don't match stored key")
		}

		// Verify the internal cache key has the correct prefix
		expectedKey := sessionKeyCachePrefixResource + resourceID
		if _, exists := client.sessionKeyCache[expectedKey]; !exists {
			t.Errorf("Cache key %q not found in cache", expectedKey)
		}
	})

	// Test SetSessionKeyByMetadataKeyID and GetSessionKeyByMetadataKeyID
	t.Run("MetadataKeyID cache operations", func(t *testing.T) {
		sessionKey2 := crypto.NewSessionKeyFromToken([]byte("another-session-key!!!!!"), "aes256")
		client.SetSessionKeyByMetadataKeyID(metadataKeyID, sessionKey2)

		retrieved := client.GetSessionKeyByMetadataKeyID(metadataKeyID)
		if retrieved == nil {
			t.Fatal("GetSessionKeyByMetadataKeyID returned nil")
		}
		// Compare contents, not pointers (getters return clones)
		if retrieved.Algo != sessionKey2.Algo || string(retrieved.Key) != string(sessionKey2.Key) {
			t.Error("Retrieved session key contents don't match stored key")
		}

		// Verify the internal cache key has the correct prefix
		expectedKey := sessionKeyCachePrefixMetaKey + metadataKeyID
		if _, exists := client.sessionKeyCache[expectedKey]; !exists {
			t.Errorf("Cache key %q not found in cache", expectedKey)
		}
	})

	// Test that different prefixes don't collide
	t.Run("Prefix collision prevention", func(t *testing.T) {
		sameID := "same-uuid-value"
		keyForResource := crypto.NewSessionKeyFromToken([]byte("resource-key-bytes!!!!!!"), "aes256")
		keyForMetadata := crypto.NewSessionKeyFromToken([]byte("metadata-key-bytes!!!!!!"), "aes256")

		client.SetSessionKeyByResourceID(sameID, keyForResource)
		client.SetSessionKeyByMetadataKeyID(sameID, keyForMetadata)

		// Retrieve both and verify they have different contents
		retrievedResource := client.GetSessionKeyByResourceID(sameID)
		retrievedMetadata := client.GetSessionKeyByMetadataKeyID(sameID)

		// Compare contents to verify no collision
		if string(retrievedResource.Key) == string(retrievedMetadata.Key) {
			t.Error("Same ID with different prefixes returned same session key contents - collision!")
		}
		// Verify each retrieved key matches its original
		if string(retrievedResource.Key) != string(keyForResource.Key) {
			t.Error("Resource session key contents don't match original")
		}
		if string(retrievedMetadata.Key) != string(keyForMetadata.Key) {
			t.Error("Metadata session key contents don't match original")
		}
	})

	// Test cache miss returns nil
	t.Run("Cache miss returns nil", func(t *testing.T) {
		if client.GetSessionKeyByResourceID("nonexistent-id") != nil {
			t.Error("Expected nil for non-existent resource ID")
		}
		if client.GetSessionKeyByMetadataKeyID("nonexistent-id") != nil {
			t.Error("Expected nil for non-existent metadata key ID")
		}
	})
}

// TestCacheThreadSafety verifies cache operations are thread-safe
func TestCacheThreadSafety(t *testing.T) {
	client := &Client{
		sessionKeyCache:    make(map[string]*crypto.SessionKey),
		pendingSessionKeys: make(map[string]*PendingSessionKey),
	}

	const numGoroutines = 10
	const numOperations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3) // 3 types of goroutines

	// Writers for resource IDs
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				resourceID := "resource-" + string(rune('A'+id))
				key := crypto.NewSessionKeyFromToken(make([]byte, 32), "aes256")
				client.SetSessionKeyByResourceID(resourceID, key)
			}
		}(i)
	}

	// Writers for metadata key IDs
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				metadataKeyID := "metakey-" + string(rune('A'+id))
				key := crypto.NewSessionKeyFromToken(make([]byte, 32), "aes256")
				client.SetSessionKeyByMetadataKeyID(metadataKeyID, key)
			}
		}(i)
	}

	// Readers mixed with cache clears
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				resourceID := "resource-" + string(rune('A'+id))
				metadataKeyID := "metakey-" + string(rune('A'+id))

				// Alternate between reads and clears
				if j%10 == 0 {
					client.ClearSessionKeyCache()
				} else {
					_ = client.GetSessionKeyByResourceID(resourceID)
					_ = client.GetSessionKeyByMetadataKeyID(metadataKeyID)
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	// If there's a race condition, this will panic or cause data corruption
	wg.Wait()

	t.Log("Concurrent cache access completed without panics or deadlocks")
}

// TestClearSessionKeyCacheZerosAllKeys verifies all keys are zeroed on clear
func TestClearSessionKeyCacheZerosAllKeys(t *testing.T) {
	client := &Client{
		sessionKeyCache:    make(map[string]*crypto.SessionKey),
		pendingSessionKeys: make(map[string]*PendingSessionKey),
	}

	// Add multiple session keys
	keys := make([]*crypto.SessionKey, 5)
	for i := 0; i < 5; i++ {
		keys[i] = crypto.NewSessionKeyFromToken(make([]byte, 32), "aes256")
		// Fill with test data
		for j := range keys[i].Key {
			keys[i].Key[j] = byte(i + j + 1)
		}
		client.SetSessionKeyByResourceID("resource-"+string(rune('A'+i)), keys[i])
	}

	// Verify keys are in cache
	if len(client.sessionKeyCache) != 5 {
		t.Fatalf("Expected 5 keys in cache, got %d", len(client.sessionKeyCache))
	}

	// Clear the cache
	client.ClearSessionKeyCache()

	// Verify cache is empty
	if len(client.sessionKeyCache) != 0 {
		t.Errorf("Expected empty cache after clear, got %d keys", len(client.sessionKeyCache))
	}

	// Verify all original keys were zeroed
	for i, key := range keys {
		if key.Key != nil {
			t.Errorf("Key %d was not set to nil", i)
		}
	}
}

// TestPendingSessionKeyOperations tests the pending session key tracking
func TestPendingSessionKeyOperations(t *testing.T) {
	client := &Client{
		sessionKeyCache:    make(map[string]*crypto.SessionKey),
		pendingSessionKeys: make(map[string]*PendingSessionKey),
	}

	// Add some pending session keys
	key1 := crypto.NewSessionKeyFromToken([]byte("session-key-1-data!!!!!"), "aes256")
	key2 := crypto.NewSessionKeyFromToken([]byte("session-key-2-data!!!!!"), "aes256")

	client.AddPendingSessionKey(ForeignModelTypesResource, "resource-1", key1)
	client.AddPendingSessionKey(ForeignModelTypesResource, "resource-2", key2)

	// Verify count
	if count := client.GetPendingSessionKeysCount(); count != 2 {
		t.Errorf("Expected 2 pending session keys, got %d", count)
	}

	// Get pending keys (should also clear the list)
	pending := client.GetPendingSessionKeys()
	if len(pending) != 2 {
		t.Errorf("Expected 2 pending keys returned, got %d", len(pending))
	}

	// Verify list is cleared
	if count := client.GetPendingSessionKeysCount(); count != 0 {
		t.Errorf("Expected 0 pending session keys after get, got %d", count)
	}

	// Verify pending keys are nil after second call
	pending2 := client.GetPendingSessionKeys()
	if pending2 != nil {
		t.Errorf("Expected nil after second GetPendingSessionKeys, got %v", pending2)
	}
}

// TestAddPendingSessionKeyNilHandling tests nil handling in AddPendingSessionKey
func TestAddPendingSessionKeyNilHandling(t *testing.T) {
	client := &Client{
		sessionKeyCache:    make(map[string]*crypto.SessionKey),
		pendingSessionKeys: make(map[string]*PendingSessionKey),
	}

	// nil session key should be ignored
	client.AddPendingSessionKey(ForeignModelTypesResource, "resource-1", nil)
	if count := client.GetPendingSessionKeysCount(); count != 0 {
		t.Errorf("Expected 0 pending keys with nil session key, got %d", count)
	}

	// Empty foreign ID should be ignored
	key := crypto.NewSessionKeyFromToken([]byte("test-key"), "aes256")
	client.AddPendingSessionKey(ForeignModelTypesResource, "", key)
	if count := client.GetPendingSessionKeysCount(); count != 0 {
		t.Errorf("Expected 0 pending keys with empty foreign ID, got %d", count)
	}
}

// TestConcurrentKeyCopy tests that GetDecryptedMetadataKeyCached properly protects
// concurrent access to the metadata key cache by returning copies.
// Each goroutine gets its own key copy, enabling true parallel decryption.
func TestConcurrentKeyCopy(t *testing.T) {
	// Create a client with the crypto mutex initialized
	pgp := crypto.PGP()
	client := &Client{
		sessionKeyCache:            make(map[string]*crypto.SessionKey),
		pendingSessionKeys:         make(map[string]*PendingSessionKey),
		decryptedMetadataKeysCache: make(map[string]*crypto.Key),
		pgp:                        pgp,
	}

	// Generate a test key pair
	keyGenHandle := pgp.KeyGeneration().AddUserId("Test User", "test@example.com").New()
	testKey, err := keyGenHandle.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Store the key in the cache (simulating what happens after login)
	client.decryptedMetadataKeysCache["test-key-id"] = testKey

	// Encrypt a test message with the key
	encHandle, err := pgp.Encryption().Recipient(testKey).New()
	if err != nil {
		t.Fatalf("Failed to create encryption handle: %v", err)
	}
	testMessage := "test metadata content"
	encryptedMsg, err := encHandle.Encrypt([]byte(testMessage))
	if err != nil {
		t.Fatalf("Failed to encrypt test message: %v", err)
	}
	armoredCiphertext, err := encryptedMsg.Armor()
	if err != nil {
		t.Fatalf("Failed to armor ciphertext: %v", err)
	}

	const numGoroutines = 10
	const numDecrypts = 20

	// Use channels to collect results
	results := make(chan error, numGoroutines*numDecrypts)
	done := make(chan struct{})

	// Start concurrent decryption goroutines
	// Each goroutine gets its own key copy from GetDecryptedMetadataKeyCached
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < numDecrypts; j++ {
				// Get a copy of the key (this is how the real code works)
				keyCopy, err := client.GetDecryptedMetadataKeyCached(context.Background(), "test-key-id")
				if err != nil {
					results <- err
					continue
				}
				// Decrypt using the copy - this can now run in parallel
				_, err = client.DecryptMetadataWithKeyID("test-key-id", keyCopy, armoredCiphertext)
				results <- err
			}
		}()
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

	// Wait for completion
	<-done

	// Verify the cache has the session key (uses metadata key ID prefix)
	if client.GetSessionKeyByMetadataKeyID("test-key-id") == nil {
		t.Error("Expected session key to be cached after concurrent decryptions")
	}

	t.Logf("Successfully completed %d concurrent decryptions without race conditions", numGoroutines*numDecrypts)
}

// TestFormatSessionKey tests the session key formatting function
func TestFormatSessionKey(t *testing.T) {
	tests := []struct {
		name     string
		key      *crypto.SessionKey
		expected string
	}{
		{
			name:     "nil key",
			key:      nil,
			expected: "",
		},
		{
			name:     "AES-256 key",
			key:      crypto.NewSessionKeyFromToken([]byte{0xDE, 0xAD, 0xBE, 0xEF}, "aes256"),
			expected: "9:DEADBEEF",
		},
		{
			name:     "AES-192 key",
			key:      crypto.NewSessionKeyFromToken([]byte{0xCA, 0xFE}, "aes192"),
			expected: "8:CAFE",
		},
		{
			name:     "AES-128 key",
			key:      crypto.NewSessionKeyFromToken([]byte{0xBA, 0xBE}, "aes128"),
			expected: "7:BABE",
		},
		{
			name:     "Unknown algorithm defaults to AES-256",
			key:      crypto.NewSessionKeyFromToken([]byte{0x12, 0x34}, "unknown"),
			expected: "9:1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatSessionKey(tt.key)
			if result != tt.expected {
				t.Errorf("FormatSessionKey() = %q, want %q", result, tt.expected)
			}
		})
	}
}
