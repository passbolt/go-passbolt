package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// MetadataSessionKey is a MetadataSessionKey
type MetadataSessionKey struct {
	ID       string `json:"id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	Data     string `json:"data,omitempty"`
	Created  Time   `json:"created,omitempty"`
	Modified Time   `json:"modified,omitempty"`
}

// MetadataSessionKeyData is a MetadataSessionKeyData
type MetadataSessionKeyData struct {
	// ObjectType Must always be PASSBOLT_SESSION_KEYS
	ObjectType  string                          `json:"object_type,omitempty"`
	SessionKeys []MetadataSessionKeyDataElement `json:"session_keys,omitempty"`
}

// MetadataSessionKeyDataElement is a MetadataSessionKeyDataElement
type MetadataSessionKeyDataElement struct {
	ForeignModel ForeignModelTypes `json:"foreign_model"`
	ForeignID    string            `json:"foreign_id"`
	SessionKey   string            `json:"session_key"`
	Modified     Time              `json:"modified"`
}

// PendingSessionKey represents a session key that was extracted during decryption
// and is pending to be saved to the server
type PendingSessionKey struct {
	ForeignModel ForeignModelTypes // "Resource", "Folder", "Tag"
	ForeignID    string            // UUID of the resource/folder/tag
	SessionKey   string            // Format: "9:HEXHEX..." (algorithm:hex-encoded key)
	Modified     Time              // When this session key was extracted
}

// GetMetadataSessionKeys gets the Metadata Session Keys
func (c *Client) GetMetadataSessionKeys(ctx context.Context) ([]MetadataSessionKey, error) {
	msg, err := c.DoCustomRequestV5(ctx, "GET", "/metadata/session-keys.json", nil, nil)
	if err != nil {
		return nil, err
	}

	var metadataSessionKeys []MetadataSessionKey
	err = json.Unmarshal(msg.Body, &metadataSessionKeys)
	if err != nil {
		return nil, err
	}
	return metadataSessionKeys, nil
}

// TODO add Create and Update

// FetchAndCacheSessionKeys fetches all metadata session keys from the server,
// decrypts the PGP message, and caches all per-resource session keys.
// The metadata_session_keys table contains ONE row per user with a SINGLE PGP message
// that, when decrypted, contains ALL session keys for all resources the user can access.
// Returns the number of session keys cached.
func (c *Client) FetchAndCacheSessionKeys(ctx context.Context) (int, error) {
	// Fetch the user's session keys row(s) from the server
	sessionKeys, err := c.GetMetadataSessionKeys(ctx)
	if err != nil {
		return 0, fmt.Errorf("get Metadata Session Keys: %w", err)
	}

	if len(sessionKeys) == 0 {
		c.log("No metadata session keys found")
		return 0, nil
	}

	totalCached := 0

	// Process each session key row (typically just one per user)
	for _, sk := range sessionKeys {
		if sk.Data == "" {
			continue
		}

		// Decrypt the PGP message with user's private key
		decryptedData, err := c.DecryptMessage(sk.Data)
		if err != nil {
			c.log("Failed to decrypt session key data: %v", err)
			continue
		}

		// Parse the JSON containing all session keys
		var sessionKeyData MetadataSessionKeyData
		err = json.Unmarshal([]byte(decryptedData), &sessionKeyData)
		if err != nil {
			c.log("Failed to parse session key data: %v", err)
			continue
		}

		// Validate object type
		if sessionKeyData.ObjectType != "PASSBOLT_SESSION_KEYS" {
			c.log("Unexpected session key object type: %s", sessionKeyData.ObjectType)
			continue
		}

		// Cache each session key by resource ID
		for _, element := range sessionKeyData.SessionKeys {
			// Only process Resource foreign model for now
			if element.ForeignModel != ForeignModelTypesResource {
				continue
			}

			if element.ForeignID == "" || element.SessionKey == "" {
				continue
			}

			// Parse session key format: "ALGO_ID:HEX_KEY" (e.g., "9:536B8D0B...")
			// Algorithm 9 = AES-256 in OpenPGP
			sessionKeyStr := element.SessionKey
			algo := "aes256" // default

			// Check for algorithm prefix (e.g., "9:" for AES-256)
			if idx := strings.Index(sessionKeyStr, ":"); idx > 0 {
				algoID := sessionKeyStr[:idx]
				sessionKeyStr = sessionKeyStr[idx+1:]

				// Map OpenPGP algorithm IDs to gopenpgp algorithm names
				switch algoID {
				case "9":
					algo = "aes256"
				case "8":
					algo = "aes192"
				case "7":
					algo = "aes128"
				default:
					c.log("Unknown algorithm ID %s for resource %s, defaulting to aes256", algoID, element.ForeignID)
				}
			}

			// Decode hex-encoded session key
			sessionKeyBytes, err := hex.DecodeString(sessionKeyStr)
			if err != nil {
				c.log("Failed to decode session key for resource %s: %v", element.ForeignID, err)
				continue
			}

			// Create a crypto.SessionKey with the appropriate algorithm
			cryptoSessionKey := crypto.NewSessionKeyFromToken(sessionKeyBytes, algo)

			// Cache by resource ID
			c.SetSessionKeyByResourceID(element.ForeignID, cryptoSessionKey)
			totalCached++
		}
	}

	c.log("Cached %d session keys from metadata_session_keys (map size: %d)", totalCached, len(c.sessionKeyCache))
	return totalCached, nil
}

// DeleteSessionKey Deletes a Passbolt SessionKey
func (c *Client) DeleteSessionKey(ctx context.Context, sessionKeyID string) error {
	err := checkUUIDFormat(sessionKeyID)
	if err != nil {
		return fmt.Errorf("checking ID format: %w", err)
	}
	_, err = c.DoCustomRequestV5(ctx, "DELETE", "/metadata/session-keys/"+sessionKeyID+".json", nil, nil)
	if err != nil {
		return err
	}
	return nil
}

// CreateSessionKeysBundle creates a new session keys bundle on the server
func (c *Client) CreateSessionKeysBundle(ctx context.Context, encryptedData string) (*MetadataSessionKey, error) {
	body := struct {
		Data string `json:"data"`
	}{
		Data: encryptedData,
	}

	msg, err := c.DoCustomRequestV5(ctx, "POST", "/metadata/session-keys.json", body, nil)
	if err != nil {
		return nil, fmt.Errorf("creating session keys bundle: %w", err)
	}

	var result MetadataSessionKey
	err = json.Unmarshal(msg.Body, &result)
	if err != nil {
		return nil, fmt.Errorf("parsing session keys bundle response: %w", err)
	}
	return &result, nil
}

// UpdateSessionKeysBundle updates an existing session keys bundle on the server.
// The modified parameter is required for optimistic locking - it must match the
// current modified timestamp on the server to prevent concurrent modifications.
func (c *Client) UpdateSessionKeysBundle(ctx context.Context, bundleID string, encryptedData string, modified Time) (*MetadataSessionKey, error) {
	err := checkUUIDFormat(bundleID)
	if err != nil {
		return nil, fmt.Errorf("checking ID format: %w", err)
	}

	body := struct {
		Data     string `json:"data"`
		Modified Time   `json:"modified"`
	}{
		Data:     encryptedData,
		Modified: modified,
	}

	msg, err := c.DoCustomRequestV5(ctx, "PUT", "/metadata/session-keys/"+bundleID+".json", body, nil)
	if err != nil {
		return nil, fmt.Errorf("updating session keys bundle: %w", err)
	}

	var result MetadataSessionKey
	err = json.Unmarshal(msg.Body, &result)
	if err != nil {
		return nil, fmt.Errorf("parsing session keys bundle response: %w", err)
	}
	return &result, nil
}

// AddPendingSessionKey adds a session key to the pending list for later saving
func (c *Client) AddPendingSessionKey(foreignModel ForeignModelTypes, foreignID string, sessionKey *crypto.SessionKey) {
	if sessionKey == nil || foreignID == "" {
		return
	}

	c.pendingSessionKeysMu.Lock()
	defer c.pendingSessionKeysMu.Unlock()

	// Format session key to string format "9:HEXHEX..."
	formattedKey := FormatSessionKey(sessionKey)

	c.pendingSessionKeys[foreignID] = &PendingSessionKey{
		ForeignModel: foreignModel,
		ForeignID:    foreignID,
		SessionKey:   formattedKey,
		Modified:     Time{Time: time.Now()},
	}
}

// GetPendingSessionKeys returns all pending session keys and clears the pending list
func (c *Client) GetPendingSessionKeys() []*PendingSessionKey {
	c.pendingSessionKeysMu.Lock()
	defer c.pendingSessionKeysMu.Unlock()

	if len(c.pendingSessionKeys) == 0 {
		return nil
	}

	result := make([]*PendingSessionKey, 0, len(c.pendingSessionKeys))
	for _, sk := range c.pendingSessionKeys {
		result = append(result, sk)
	}

	// Clear the pending map
	c.pendingSessionKeys = make(map[string]*PendingSessionKey)

	return result
}

// GetPendingSessionKeysCount returns the number of pending session keys without clearing
func (c *Client) GetPendingSessionKeysCount() int {
	c.pendingSessionKeysMu.RLock()
	defer c.pendingSessionKeysMu.RUnlock()
	return len(c.pendingSessionKeys)
}

// FormatSessionKey converts a crypto.SessionKey to the server format "9:HEXHEX..."
func FormatSessionKey(sk *crypto.SessionKey) string {
	if sk == nil {
		return ""
	}

	algoID := "9" // Default AES-256
	switch sk.Algo {
	case "aes256":
		algoID = "9"
	case "aes192":
		algoID = "8"
	case "aes128":
		algoID = "7"
	}

	return algoID + ":" + strings.ToUpper(hex.EncodeToString(sk.Key))
}

// SavePendingSessionKeys saves all pending session keys to the server.
// It fetches existing bundles, merges with pending keys, encrypts, and saves.
// Returns the number of session keys saved.
func (c *Client) SavePendingSessionKeys(ctx context.Context) (int, error) {
	// Get pending session keys (this clears the pending list)
	pending := c.GetPendingSessionKeys()
	if len(pending) == 0 {
		c.log("No pending session keys to save")
		return 0, nil
	}

	c.log("Saving %d pending session keys to server", len(pending))

	// Fetch existing bundles from server
	existingBundles, err := c.GetMetadataSessionKeys(ctx)
	if err != nil {
		return 0, fmt.Errorf("fetching existing session keys: %w", err)
	}

	// Build a map of existing session keys (foreign_id -> element)
	existingKeys := make(map[string]MetadataSessionKeyDataElement)

	c.log("Found %d existing bundles on server", len(existingBundles))

	for _, bundle := range existingBundles {
		if bundle.Data == "" {
			continue
		}

		// Decrypt the existing bundle
		decryptedData, err := c.DecryptMessage(bundle.Data)
		if err != nil {
			c.log("Failed to decrypt existing session key bundle: %v", err)
			continue
		}

		var bundleData MetadataSessionKeyData
		err = json.Unmarshal([]byte(decryptedData), &bundleData)
		if err != nil {
			c.log("Failed to parse existing session key bundle: %v", err)
			continue
		}

		c.log("Existing bundle has %d session keys", len(bundleData.SessionKeys))

		// Add existing keys to the map
		for _, element := range bundleData.SessionKeys {
			existingKeys[element.ForeignID] = element
		}
	}

	c.log("Total existing keys after merge: %d, pending keys: %d", len(existingKeys), len(pending))

	// Merge: pending keys override existing keys (or add new ones)
	for _, pk := range pending {
		existingKeys[pk.ForeignID] = MetadataSessionKeyDataElement{
			ForeignModel: pk.ForeignModel,
			ForeignID:    pk.ForeignID,
			SessionKey:   pk.SessionKey,
			Modified:     pk.Modified,
		}
	}

	// Build the merged bundle data
	mergedKeys := make([]MetadataSessionKeyDataElement, 0, len(existingKeys))
	for _, element := range existingKeys {
		mergedKeys = append(mergedKeys, element)
	}

	bundleData := MetadataSessionKeyData{
		ObjectType:  "PASSBOLT_SESSION_KEYS",
		SessionKeys: mergedKeys,
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(bundleData)
	if err != nil {
		return 0, fmt.Errorf("marshaling session keys bundle: %w", err)
	}

	c.log("JSON data size: %d bytes for %d keys", len(jsonData), len(mergedKeys))

	// Encrypt with user's public key
	encryptedData, err := c.EncryptMessage(string(jsonData))
	if err != nil {
		return 0, fmt.Errorf("encrypting session keys bundle: %w", err)
	}

	// Save to server (create or update)
	if len(existingBundles) > 0 {
		// Update the first (most recent) bundle, passing the modified timestamp for optimistic locking
		_, err = c.UpdateSessionKeysBundle(ctx, existingBundles[0].ID, encryptedData, existingBundles[0].Modified)
		if err != nil {
			return 0, fmt.Errorf("updating session keys bundle: %w", err)
		}
		c.log("Updated session keys bundle %s with %d total keys", existingBundles[0].ID, len(mergedKeys))
	} else {
		// Create new bundle
		result, err := c.CreateSessionKeysBundle(ctx, encryptedData)
		if err != nil {
			return 0, fmt.Errorf("creating session keys bundle: %w", err)
		}
		c.log("Created session keys bundle %s with %d keys", result.ID, len(mergedKeys))
	}

	// Delete old bundles (keep only the first one)
	for i := 1; i < len(existingBundles); i++ {
		if err := c.DeleteSessionKey(ctx, existingBundles[i].ID); err != nil {
			c.log("Failed to delete old session key bundle %s: %v", existingBundles[i].ID, err)
		}
	}

	return len(pending), nil
}
