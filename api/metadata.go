package api

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

const PassboltObjectTypeResourceMetadata = "PASSBOLT_RESOURCE_METADATA"
const PassboltObjectTypeSecretData = "PASSBOLT_SECRET_DATA"

// DecryptMetadata decrypts metadata using the provided key.
// For session key caching, use DecryptMetadataWithKeyID instead.
func (c *Client) DecryptMetadata(metadataKey *crypto.Key, armoredCiphertext string) (string, error) {
	return c.DecryptMetadataWithKeyID("", metadataKey, armoredCiphertext)
}

// DecryptMetadataWithKeyID decrypts metadata using the provided key and caches the session key.
// The metadataKeyID is used as the cache key for session key caching.
// If metadataKeyID is empty, session key caching is disabled.
// For resource-aware caching (using pre-fetched session keys), use DecryptMetadataWithResourceID instead.
// This method is thread-safe: multiple goroutines can call this method concurrently with the same metadataKey.
func (c *Client) DecryptMetadataWithKeyID(metadataKeyID string, metadataKey *crypto.Key, armoredCiphertext string) (string, error) {
	// Try to get session key from cache (returns a clone)
	if metadataKeyID != "" {
		if sessionKeyClone := c.GetSessionKeyByMetadataKeyID(metadataKeyID); sessionKeyClone != nil {
			message, err := c.DecryptMessageWithSessionKey(sessionKeyClone, armoredCiphertext)
			// If decrypt was successful, return immediately
			if err == nil {
				return message, nil
			}
			// If failed, fall through to full decryption
			c.log("Session key cache miss for metadata key %v, falling back to full decryption", metadataKeyID)
		}
	}

	// Use the locked, copying variant: the underlying direct decryption defers
	// ClearPrivateParams which would otherwise mutate the caller's metadataKey,
	// breaking subsequent calls and racing across goroutines.
	metadata, newSessionKey, err := c.DecryptMessageWithPrivateKeyAndReturnSessionKey(metadataKey, armoredCiphertext)
	if err != nil {
		return "", fmt.Errorf("decrypting Metadata: %w", err)
	}

	// Cache the session key for future use (clone it to avoid Clear() corruption)
	// When gopenpgp's ClearPrivateParams() is called, it zeros out the SessionKey.Key bytes.
	// We clone the session key to create an independent copy that won't be affected.
	if metadataKeyID != "" && newSessionKey != nil {
		clonedSessionKey := crypto.NewSessionKeyFromToken(newSessionKey.Key, newSessionKey.Algo)
		c.SetSessionKeyByMetadataKeyID(metadataKeyID, clonedSessionKey)
	}

	return metadata, nil
}

// DecryptMetadataWithResourceID decrypts metadata with resource-aware session key caching.
// It first checks for a pre-fetched session key by resource ID (from metadata_session_keys table),
// then falls back to metadata key ID cache, and finally to full asymmetric decryption.
// This function provides the best performance when PreFetchCaches() has been called.
// This method is thread-safe: multiple goroutines can call this method concurrently with the same metadataKey.
func (c *Client) DecryptMetadataWithResourceID(resourceID, metadataKeyID string, metadataKey *crypto.Key, armoredCiphertext string) (string, error) {
	// 1. First, check for pre-fetched session key by resource ID (returns a clone)
	if resourceID != "" {
		if sessionKeyClone := c.GetSessionKeyByResourceID(resourceID); sessionKeyClone != nil {
			message, err := c.DecryptMessageWithSessionKey(sessionKeyClone, armoredCiphertext)
			if err == nil {
				c.log("Metadata session key cache HIT for resource %v", resourceID)
				return message, nil
			}
			// If failed, fall through to other cache strategies
			c.log("Resource session key cache decrypt FAILED for resource %v: %v", resourceID, err)
		} else {
			c.sessionKeyCacheMu.RLock()
			cacheSize := len(c.sessionKeyCache)
			c.sessionKeyCacheMu.RUnlock()
			c.log("Resource session key cache MISS for resource %v (cache size: %d)", resourceID, cacheSize)
		}
	}

	// 2. Check metadata key ID cache (fallback, returns a clone)
	if metadataKeyID != "" {
		if sessionKeyClone := c.GetSessionKeyByMetadataKeyID(metadataKeyID); sessionKeyClone != nil {
			message, err := c.DecryptMessageWithSessionKey(sessionKeyClone, armoredCiphertext)
			if err == nil {
				return message, nil
			}
			c.log("Metadata key session cache miss for %v, falling back to full decryption", metadataKeyID)
		}
	}

	// 3. Full asymmetric decryption — use the locked, copying variant so the
	// underlying defer ClearPrivateParams doesn't mutate the caller's metadataKey.
	metadata, newSessionKey, err := c.DecryptMessageWithPrivateKeyAndReturnSessionKey(metadataKey, armoredCiphertext)
	if err != nil {
		return "", fmt.Errorf("decrypting Metadata: %w", err)
	}

	// Cache the session key by resource ID if available
	if newSessionKey != nil {
		clonedSessionKey := crypto.NewSessionKeyFromToken(newSessionKey.Key, newSessionKey.Algo)
		if resourceID != "" {
			c.SetSessionKeyByResourceID(resourceID, clonedSessionKey)
			// Also add to pending session keys for saving to server
			c.AddPendingSessionKey(ForeignModelTypesResource, resourceID, newSessionKey)
		} else if metadataKeyID != "" {
			c.SetSessionKeyByMetadataKeyID(metadataKeyID, clonedSessionKey)
		}
	}

	return metadata, nil
}

func (c *Client) EncryptMetadata(metadataKey *crypto.Key, data string) (string, error) {
	armoredCiphertext, err := c.EncryptMessageWithKey(metadataKey, data)
	if err != nil {
		return "", fmt.Errorf("encrypting Metadata: %w", err)
	}

	return armoredCiphertext, nil
}
