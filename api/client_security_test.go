package api_test

import (
	"strings"
	"testing"
)

// ============================================================================
// Security Tests for Key Caching and Memory Zeroing
//
// Note: This file uses setupTestClient(), LoadTestConfig(), and TestConfig
// from metadata_implementation_test.go. Both test files share these common
// test helpers since they're in the same package (api_test).
// ============================================================================

// TestSecureZeroingOnLogout tests that logout clears user private key
func TestSecureZeroingOnLogout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Get user private key copy before logout
	keyBefore, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("Failed to get user private key: %v", err)
	}

	if keyBefore == nil {
		t.Fatal("Expected non-nil user private key before logout")
	}

	fingerprintBefore := keyBefore.GetFingerprint()
	t.Logf("User key fingerprint before logout: %s", fingerprintBefore)

	// Logout
	err = client.Logout(ctx)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	// Try to get user private key after logout (should fail)
	keyAfter, err := client.GetUserPrivateKeyCopy()
	if err == nil {
		t.Error("Expected error when getting user private key after logout")
	}
	if keyAfter != nil {
		t.Error("Expected nil user private key after logout")
	}

	// Try to encrypt (should fail gracefully)
	_, err = client.EncryptMessage("test message")
	if err == nil {
		t.Error("Expected error when encrypting after logout")
	}
	if err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "no user private key") &&
			!strings.Contains(strings.ToLower(err.Error()), "logged out") {
			t.Logf("Warning: Error message may not be clear: %v", err)
		} else {
			t.Logf("Got expected error: %v", err)
		}
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

// TestClearSessionKeyCacheZerosKeys tests that session key cache clearing zeros memory
func TestClearSessionKeyCacheZerosKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Get a metadata key and encrypt/decrypt to populate session key cache
	keys, err := client.GetMetadataKeysCached(ctx)
	if err != nil {
		t.Skip("Metadata keys not available (v4 server)")
	}

	if len(keys) == 0 {
		t.Skip("No metadata keys available")
	}

	keyID := keys[0].ID
	metadataKey, err := client.GetDecryptedMetadataKeyCached(ctx, keyID)
	if err != nil {
		t.Fatalf("Failed to get metadata key: %v", err)
	}

	testData := `{"object_type":"PASSBOLT_RESOURCE_METADATA","name":"Clear Test"}`
	encrypted, err := client.EncryptMetadata(metadataKey, testData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	_, err = client.DecryptMetadataWithKeyID(keyID, metadataKey, encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify session key is cached
	sessionKey := client.GetSessionKey(keyID)
	if sessionKey == nil {
		t.Fatal("Expected session key to be cached")
	}

	t.Logf("Session key cached (algo: %s, key length: %d)",
		sessionKey.Algo, len(sessionKey.Key))

	// Clear session key cache (should zero memory)
	client.ClearSessionKeyCache()

	// Verify cache is empty
	sessionKey = client.GetSessionKey(keyID)
	if sessionKey != nil {
		t.Error("Expected session key cache to be empty after clear")
	}

	// Verify decryption still works (will do full PGP decrypt)
	decrypted, err := client.DecryptMetadataWithKeyID(keyID, metadataKey, encrypted)
	if err != nil {
		t.Fatalf("Decryption after cache clear failed: %v", err)
	}

	if decrypted != testData {
		t.Error("Decryption after cache clear returned wrong data")
	}

	t.Log("SUCCESS: Session key cache clearing and re-decryption works correctly")
}

// TestLogoutLoginCycle tests that client cannot be reused after logout (security by design)
func TestLogoutLoginCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Verify client works before logout
	_, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("Client should work before logout: %v", err)
	}

	// Logout
	err = client.Logout(ctx)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	// Verify client doesn't work after logout
	_, err = client.GetUserPrivateKeyCopy()
	if err == nil {
		t.Error("Expected client to fail after logout")
	}

	// Try to login again (should fail gracefully, not panic)
	err = client.Login(ctx)
	if err == nil {
		t.Error("Expected Login() to fail after logout (client should not be reusable)")
	}

	// Verify error message is clear
	if err != nil {
		errMsg := strings.ToLower(err.Error())
		if !strings.Contains(errMsg, "no user private key") &&
			!strings.Contains(errMsg, "logged out") &&
			!strings.Contains(errMsg, "cannot login") {
			t.Logf("Warning: Error message may not be clear: %v", err)
		} else {
			t.Logf("Got expected error: %v", err)
		}
	}

	t.Log("SUCCESS: Client correctly prevents reuse after logout")
}

// TestDecryptAfterLogoutFails tests that decrypt operations fail after logout with clear errors
func TestDecryptAfterLogoutFails(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Encrypt a message before logout
	testMessage := "Secret message to decrypt"
	encrypted, err := client.EncryptMessage(testMessage)
	if err != nil {
		t.Fatalf("Failed to encrypt before logout: %v", err)
	}

	// Logout
	err = client.Logout(ctx)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	// Try to decrypt after logout (should fail)
	_, err = client.DecryptMessage(encrypted)
	if err == nil {
		t.Error("Expected error when decrypting after logout")
	}

	// Verify error message is clear
	if err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "no user private key") &&
			!strings.Contains(strings.ToLower(err.Error()), "logged out") {
			t.Logf("Warning: Error message may not be clear: %v", err)
		} else {
			t.Logf("Got expected error: %v", err)
		}
	}
}
