package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/google/go-querystring/query"
)

// Session key cache key prefixes for metadata decryption
const (
	// sessionKeyCachePrefixResource is used for per-resource METADATA session keys from metadata_session_keys table
	// These are shared keys used to decrypt resource metadata (name, username, URIs, etc.)
	sessionKeyCachePrefixResource = "resource:"
	// sessionKeyCachePrefixMetaKey is used for fallback session keys keyed by metadata key ID
	sessionKeyCachePrefixMetaKey = "metakey:"
)

// Client is a Client struct for the Passbolt api.
// The Client is thread-safe for concurrent use. All crypto operations and cache
// access are protected by internal mutexes.
type Client struct {
	baseURL    *url.URL
	userAgent  string
	httpClient *http.Client

	sessionToken http.Cookie
	csrfToken    http.Cookie
	mfaToken     http.Cookie

	// userPublicKey has been removed since it can be gotten from the private userPrivateKey

	// be sure to make a copy since using ClearPrivateParams on a handler also wipes the key...
	userPrivateKey *crypto.Key
	userID         string

	// Mutex to protect userPrivateKey and crypto operations for thread safety.
	// This ensures that concurrent encryption/decryption operations don't race
	// on the userPrivateKey.Copy() operation which is not thread-safe.
	cryptoMu sync.RWMutex

	// Server Settings Determining which Resource Types we can use
	metadataTypeSettings MetadataTypeSettings

	// Server Settings Determining which Metadata Keys to use
	metadataKeySettings MetadataKeySettings

	// Server Settings for password expiry
	passwordExpirySettings PasswordExpirySettings
	// trusted metadatakey, Shared Metadata Keys which are trusted for encryption
	trustedMetadataKeyFingerprint *string
	trustedMetadataKeySigntime    *time.Time

	// MetadataKeyUpdatedCallback is Called by the Client when the Metadatakey has changed
	// trusted shows if this key has been signed and thus been trusted by another client of this user
	// the consumer should prompt the user about the keychange and save the new fingerprint (may be skipped if it is trusted).
	// If no error is returned then the new key will be accepted and its fingerprint set in the client
	MetadataKeyUpdatedCallback func(ctx context.Context, trusted bool, fingerprint string, signTime time.Time) error

	// used for solving MFA challenges. You can block this to for example wait for user input.
	// You shouden't run any unrelated API Calls while you are in this callback.
	// You need to Return the Cookie that Passbolt expects to verify you MFA, usually it is called passbolt_mfa
	MFACallback func(ctx context.Context, c *Client, res *APIResponse) (http.Cookie, error)

	// gopengpg Handler, allow for custom settings in the future
	pgp *crypto.PGPHandle

	// Enable Debug Logging
	Debug bool

	// Cache for resource types (rarely change)
	resourceTypesCache   []ResourceType
	resourceTypesCacheMu sync.RWMutex

	// Cache for metadata keys (includes decrypted private keys)
	metadataKeysCache []MetadataKey
	// Cache for decrypted metadata private keys, keyed by metadata key ID
	decryptedMetadataKeysCache map[string]*crypto.Key

	// Cache for session keys used for metadata decryption, keyed by metadata key ID
	sessionKeyCache map[string]*crypto.SessionKey
	// Mutex to protect sessionKeyCache for concurrent access
	sessionKeyCacheMu sync.RWMutex

	// Pending session keys to be saved to the server (collected during decryption)
	pendingSessionKeys map[string]*PendingSessionKey
	// Mutex to protect pendingSessionKeys for concurrent access
	pendingSessionKeysMu sync.RWMutex
}

// PublicKeyReponse the Body of a Public Key Api Request
type PublicKeyReponse struct {
	Fingerprint string `json:"fingerprint"`
	Keydata     string `json:"keydata"`
}

// NewClient Returns a new Passbolt Client.
// if httpClient is nil http.DefaultClient will be used.
// if UserAgent is "" "goPassboltClient/1.0" will be used.
// if UserPrivateKey is "" Key Setup is Skipped to Enable using the Client for User Registration, Most other function will be broken.
// After Registration a new Client Should be Created.
func NewClient(httpClient *http.Client, UserAgent, BaseURL, UserPrivateKey, UserPassword string) (*Client, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if UserAgent == "" {
		UserAgent = "goPassboltClient/1.0"
	}

	u, err := url.Parse(BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing Base URL: %w", err)
	}

	pgp := crypto.PGP()

	var unlockedKey *crypto.Key = nil
	if UserPrivateKey != "" {
		key, err := GetPrivateKeyFromArmor(UserPrivateKey, []byte(UserPassword))
		if err != nil {
			return nil, fmt.Errorf("get Private Key: %w", err)
		}
		unlockedKey = key
	}

	// Create Client Object
	c := &Client{
		httpClient:                 httpClient,
		baseURL:                    u,
		userAgent:                  UserAgent,
		userPrivateKey:             unlockedKey,
		pgp:                        pgp,
		decryptedMetadataKeysCache: make(map[string]*crypto.Key),
		sessionKeyCache:            make(map[string]*crypto.SessionKey),
		pendingSessionKeys:         make(map[string]*PendingSessionKey),
	}
	return c, err
}

func (c *Client) newRequest(method, url string, body interface{}) (*http.Request, error) {
	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, fmt.Errorf("JSON encoding Request: %w", err)
		}
	}

	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP Request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("X-CSRF-Token", c.csrfToken.Value)
	req.AddCookie(&c.sessionToken)
	req.AddCookie(&c.csrfToken)
	if c.mfaToken.Name != "" {
		req.AddCookie(&c.mfaToken)
	}

	// Debugging
	c.log("Request URL: %v", req.URL.String())
	if c.Debug && body != nil {
		data, err := json.Marshal(body)
		if err == nil {
			c.log("Raw Request: %v", string(data))
		}
	}

	return req, nil
}

func (c *Client) do(ctx context.Context, req *http.Request, v *APIResponse) (*http.Response, error) {
	req = req.WithContext(ctx)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("request Context: %w", ctx.Err())
		default:
			return nil, fmt.Errorf("request: %w", err)
		}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, fmt.Errorf("error reading Response Body: %w", err)
	}

	c.log("Raw Response: %v", string(bodyBytes))

	err = json.Unmarshal(bodyBytes, v)
	if err != nil {
		return resp, fmt.Errorf("unable to Parse JSON API Response with HTTP Status Code %v: %w", resp.StatusCode, err)
	}

	return resp, nil
}

func (c *Client) log(msg string, args ...interface{}) {
	if !c.Debug {
		return
	}
	fmt.Printf("[go-passbolt] "+msg+"\n", args...)
}

func generateURL(base url.URL, p string, opt interface{}) (string, error) {
	base.Path = path.Join(base.Path, p)
	vs, err := query.Values(opt)
	if err != nil {
		return "", fmt.Errorf("getting URL Query Values: %w", err)
	}
	base.RawQuery = vs.Encode()

	return base.String(), nil
}

// GetUserID Gets the ID of the Current User
func (c *Client) GetUserID() string {
	return c.userID
}

// GetPublicKey gets the Public Key and Fingerprint of the Passbolt instance
func (c *Client) GetPublicKey(ctx context.Context) (string, string, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", "/auth/verify.json", "v2", nil, nil)
	if err != nil {
		return "", "", fmt.Errorf("doing Request: %w", err)
	}

	var body PublicKeyReponse
	err = json.Unmarshal(msg.Body, &body)
	if err != nil {
		return "", "", fmt.Errorf("parsing JSON: %w", err)
	}

	// Lets get the actual Fingerprint instead of trusting the Server
	serverKey, err := crypto.NewKeyFromArmored(body.Keydata)
	if err != nil {
		return "", "", fmt.Errorf("parsing Server Key: %w", err)
	}
	return body.Keydata, serverKey.GetFingerprint(), nil
}

// setMetadataTypeSettings Gets and configures the Client to use the Types the Server wants us to use
func (c *Client) setMetadataTypeSettings(ctx context.Context, settings *ServerSettingsResponse) error {
	if settings.Passbolt.IsPluginEnabled("metadata") {
		c.log("Server has metadata plugin enabled, is v5 or Higher")
		metadataTypeSettings, err := c.GetServerMetadataTypeSettings(ctx)
		if err != nil {
			return fmt.Errorf("getting Metadata Type Settings: %w", err)
		}

		c.log("metadataTypeSettings: %+v", metadataTypeSettings)
		c.metadataTypeSettings = *metadataTypeSettings

		metadataKeySettings, err := c.GetServerMetadataKeySettings(ctx)
		if err != nil {
			return fmt.Errorf("getting Metadata Key Settings: %w", err)
		}

		c.log("metadataKeySettings: %+v", metadataKeySettings)
		c.metadataKeySettings = *metadataKeySettings
	} else {
		c.log("Server has metadata plugin disabled or not installed, Server is v4")
		c.metadataTypeSettings = getV4DefaultMetadataTypeSettings()
		c.metadataKeySettings = MetadataKeySettings{
			AllowUsageOfPersonalKeys:   true,
			AllowZeroKnowledgeKeyShare: false,
		}
	}
	return nil
}

// setPasswordExpirySettings fetches and configures the Client to use the password expiry plugin
func (c *Client) setPasswordExpirySettings(ctx context.Context, settings *ServerSettingsResponse) error {
	if settings.Passbolt.IsPluginEnabled("passwordExpiry") && settings.Passbolt.IsPluginEnabled("passwordExpiryPolicies") {
		c.log("Server has password expiry plugin enabled.")
		passwordExpirySettings, err := c.getServerPasswordExpirySettings(ctx)
		if err != nil {
			return fmt.Errorf("getting Password Expiry Settings: %w", err)
		}

		c.log("passwordExpirySettings: %+v", passwordExpirySettings)
		c.passwordExpirySettings = *passwordExpirySettings
	} else {
		c.log("Server has password expiry plugin disabled or not installed.")
		c.passwordExpirySettings = getDefaultPasswordExpirySettings()
	}

	return nil
}

// GetPGPHandle Gets the Gopgenpgp Handler
func (c *Client) GetPGPHandle() *crypto.PGPHandle {
	return c.pgp
}

// GetPasswordExpirySettings returns the password expiry settings for the client
func (c *Client) GetPasswordExpirySettings() PasswordExpirySettings {
	return c.passwordExpirySettings
}

// ClearCache clears all cached data
func (c *Client) ClearCache() {
	c.ClearResourceTypesCache()
	c.ClearMetadataKeysCache()
	c.ClearSessionKeyCache()
}

// ClearResourceTypesCache clears the resource types cache
func (c *Client) ClearResourceTypesCache() {
	c.resourceTypesCacheMu.Lock()
	c.resourceTypesCache = nil
	c.resourceTypesCacheMu.Unlock()
}

// ClearMetadataKeysCache clears the metadata keys cache with secure memory zeroing
func (c *Client) ClearMetadataKeysCache() {
	c.cryptoMu.Lock()
	defer c.cryptoMu.Unlock()

	c.metadataKeysCache = nil

	// Securely zero all cached decrypted keys before clearing
	for keyID, key := range c.decryptedMetadataKeysCache {
		secureZeroCryptoKey(key)
		delete(c.decryptedMetadataKeysCache, keyID)
	}

	c.decryptedMetadataKeysCache = make(map[string]*crypto.Key)
}

// ClearSessionKeyCache clears the session key cache with secure memory zeroing
func (c *Client) ClearSessionKeyCache() {
	c.sessionKeyCacheMu.Lock()
	defer c.sessionKeyCacheMu.Unlock()

	// Securely zero all cached session keys before clearing
	for keyID, sessionKey := range c.sessionKeyCache {
		secureZeroSessionKey(sessionKey)
		delete(c.sessionKeyCache, keyID)
	}

	c.sessionKeyCache = make(map[string]*crypto.SessionKey)
}

// secureZeroCryptoKey securely zeros a crypto.Key's private parameters
// Uses gopenpgp's ClearPrivateParams() which zeros RSA/DSA/ElGamal big.Ints
// and EdDSA/ECDH/X25519 byte arrays before setting pointers to nil
func secureZeroCryptoKey(key *crypto.Key) {
	if key != nil {
		key.ClearPrivateParams()
	}
}

// secureZeroSessionKey securely zeros a crypto.SessionKey's key bytes
// SessionKey has no built-in Clear() method, so we manually zero the byte array
func secureZeroSessionKey(sessionKey *crypto.SessionKey) {
	if sessionKey != nil && sessionKey.Key != nil {
		// Explicitly zero each byte
		for i := range sessionKey.Key {
			sessionKey.Key[i] = 0
		}
		sessionKey.Key = nil
	}
}

// cloneSessionKey creates a copy of a session key to prevent modification of cached keys
func cloneSessionKey(sk *crypto.SessionKey) *crypto.SessionKey {
	if sk == nil {
		return nil
	}
	return crypto.NewSessionKeyFromToken(sk.Key, sk.Algo)
}

// GetResourceTypesCached returns cached resource types, fetching from API if cache is empty
func (c *Client) GetResourceTypesCached(ctx context.Context) ([]ResourceType, error) {
	c.resourceTypesCacheMu.RLock()
	if c.resourceTypesCache != nil {
		result := c.resourceTypesCache
		c.resourceTypesCacheMu.RUnlock()
		return result, nil
	}
	c.resourceTypesCacheMu.RUnlock()

	types, err := c.GetResourceTypes(ctx, nil)
	if err != nil {
		return nil, err
	}

	c.resourceTypesCacheMu.Lock()
	c.resourceTypesCache = types
	c.resourceTypesCacheMu.Unlock()
	return types, nil
}

// GetResourceTypeCached returns a cached resource type by ID, fetching from API if not in cache
func (c *Client) GetResourceTypeCached(ctx context.Context, typeID string) (*ResourceType, error) {
	// First check the cache
	c.resourceTypesCacheMu.RLock()
	if c.resourceTypesCache != nil {
		for i := range c.resourceTypesCache {
			if c.resourceTypesCache[i].ID == typeID {
				result := &c.resourceTypesCache[i]
				c.resourceTypesCacheMu.RUnlock()
				return result, nil
			}
		}
		c.resourceTypesCacheMu.RUnlock()
	} else {
		c.resourceTypesCacheMu.RUnlock()
	}

	// Populate cache and search again
	types, err := c.GetResourceTypesCached(ctx)
	if err != nil {
		return nil, err
	}

	for i := range types {
		if types[i].ID == typeID {
			return &types[i], nil
		}
	}

	return nil, fmt.Errorf("%w: %v", ErrResourceTypeNotFound, typeID)
}

// GetResourceTypeBySlugCached returns a cached resource type by slug
func (c *Client) GetResourceTypeBySlugCached(ctx context.Context, slug string) (*ResourceType, error) {
	types, err := c.GetResourceTypesCached(ctx)
	if err != nil {
		return nil, err
	}

	for i := range types {
		if types[i].Slug == slug {
			return &types[i], nil
		}
	}

	return nil, fmt.Errorf("%w: %v", ErrResourceTypeNotFound, slug)
}

// GetMetadataKeysCached returns cached metadata keys, fetching from API if cache is empty
func (c *Client) GetMetadataKeysCached(ctx context.Context) ([]MetadataKey, error) {
	c.cryptoMu.RLock()
	if c.metadataKeysCache != nil {
		result := c.metadataKeysCache
		c.cryptoMu.RUnlock()
		return result, nil
	}
	c.cryptoMu.RUnlock()

	keys, err := c.GetMetadataKeys(ctx, &GetMetadataKeysOptions{
		ContainMetadataPrivateKeys: true,
	})
	if err != nil {
		return nil, err
	}

	c.cryptoMu.Lock()
	c.metadataKeysCache = keys
	c.cryptoMu.Unlock()
	return keys, nil
}

// GetDecryptedMetadataKeyCached returns a copy of a cached decrypted metadata key by ID.
// If not in cache, it will fetch and decrypt the key.
//
// The returned key is a copy that the caller owns and can use without synchronization.
// This allows multiple goroutines to decrypt metadata concurrently without contention.
func (c *Client) GetDecryptedMetadataKeyCached(ctx context.Context, id string) (*crypto.Key, error) {
	// Check decrypted key cache first
	// We need an exclusive lock because Key.Copy() is not thread-safe when called
	// on the same key concurrently. This is a brief lock just for the copy operation.
	c.cryptoMu.Lock()
	key, ok := c.decryptedMetadataKeysCache[id]
	if ok {
		// Return a copy so the caller can use it without synchronization
		keyCopy, err := key.Copy()
		c.cryptoMu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("copy Cached Metadata Key: %w", err)
		}
		return keyCopy, nil
	}
	c.cryptoMu.Unlock()

	// Get metadata keys (from cache or API)
	keys, err := c.GetMetadataKeysCached(ctx)
	if err != nil {
		return nil, fmt.Errorf("get Metadata Keys: %w", err)
	}

	// Find the key with matching ID
	var metadataKey *MetadataKey
	for i := range keys {
		if keys[i].ID == id {
			metadataKey = &keys[i]
			break
		}
	}

	if metadataKey == nil {
		return nil, fmt.Errorf("%w: %v", ErrMetadataKeyNotFound, id)
	}

	if len(metadataKey.MetadataPrivateKeys) == 0 {
		return nil, ErrNoMetadataPrivateKey
	}

	// Find our user's private key
	var privMetadata *MetadataPrivateKey
	for i := range metadataKey.MetadataPrivateKeys {
		if metadataKey.MetadataPrivateKeys[i].UserID != nil && *metadataKey.MetadataPrivateKeys[i].UserID == c.userID {
			privMetadata = &metadataKey.MetadataPrivateKeys[i]
			break
		}
	}

	if privMetadata == nil {
		return nil, fmt.Errorf("%w: user id %v", ErrNoMetadataPrivateKey, c.userID)
	}

	decPrivMetadatakey, err := c.DecryptMessage(privMetadata.Data)
	if err != nil {
		return nil, fmt.Errorf("decrypt Metadata Private Key Data: %w", err)
	}

	var data MetadataPrivateKeyData
	err = json.Unmarshal([]byte(decPrivMetadatakey), &data)
	if err != nil {
		return nil, fmt.Errorf("parse Metadata Private Key Data: %w", err)
	}

	metadataPrivateKeyObj, err := GetPrivateKeyFromArmor(data.ArmoredKey, []byte(data.Passphrase))
	if err != nil {
		return nil, fmt.Errorf("get Metadata Private Key: %w", err)
	}

	// Cache the decrypted key
	c.cryptoMu.Lock()
	c.decryptedMetadataKeysCache[id] = metadataPrivateKeyObj
	c.cryptoMu.Unlock()

	// Return a copy so caller cannot affect cached key
	keyCopy, err := metadataPrivateKeyObj.Copy()
	if err != nil {
		return nil, fmt.Errorf("copy Metadata Key: %w", err)
	}
	return keyCopy, nil
}

// PreDecryptAllMetadataPrivateKeys pre-decrypts all metadata private keys and caches them.
// This is typically called during login to avoid lazy decryption later.
// Returns the number of keys decrypted.
func (c *Client) PreDecryptAllMetadataPrivateKeys(ctx context.Context) (int, error) {
	// Fetch all metadata keys (this will also fetch the private keys for our user)
	keys, err := c.GetMetadataKeysCached(ctx)
	if err != nil {
		return 0, fmt.Errorf("get Metadata Keys: %w", err)
	}

	decrypted := 0
	for _, key := range keys {
		// Attempt to decrypt and cache each key
		_, err := c.GetDecryptedMetadataKeyCached(ctx, key.ID)
		if err != nil {
			c.log("Failed to pre-decrypt metadata key %s: %v", key.ID, err)
			continue
		}
		decrypted++
	}

	c.log("Pre-decrypted %d metadata private keys", decrypted)
	return decrypted, nil
}

// PreFetchCaches pre-fetches and caches session keys and metadata private keys.
// This should be called after Login() when the server supports v5 metadata.
// Returns the count of session keys cached, metadata keys decrypted, and any error.
func (c *Client) PreFetchCaches(ctx context.Context) (sessionCount, metadataKeyCount int, err error) {
	// First, fetch and cache session keys from metadata_session_keys table
	sessionCount, err = c.FetchAndCacheSessionKeys(ctx)
	if err != nil {
		// Log but don't fail - session key caching is optional optimization
		c.log("Warning: Failed to fetch session keys: %v", err)
		err = nil //nolint:ineffassign // intentional: clear error to continue
	}

	// Then, pre-decrypt all metadata private keys
	metadataKeyCount, err = c.PreDecryptAllMetadataPrivateKeys(ctx)
	if err != nil {
		// Log but don't fail - this is also optional optimization
		c.log("Warning: Failed to pre-decrypt metadata keys: %v", err)
		err = nil //nolint:ineffassign // intentional: clear error to continue
	}

	return sessionCount, metadataKeyCount, nil
}

// GetSessionKeyByResourceID retrieves a cached session key by resource ID.
// These session keys come from the metadata_session_keys table.
// Returns a clone of the cached key to prevent callers from modifying the cache.
func (c *Client) GetSessionKeyByResourceID(resourceID string) *crypto.SessionKey {
	c.sessionKeyCacheMu.RLock()
	defer c.sessionKeyCacheMu.RUnlock()
	return cloneSessionKey(c.sessionKeyCache[sessionKeyCachePrefixResource+resourceID])
}

// SetSessionKeyByResourceID stores a session key for a specific resource ID
func (c *Client) SetSessionKeyByResourceID(resourceID string, sessionKey *crypto.SessionKey) {
	c.sessionKeyCacheMu.Lock()
	defer c.sessionKeyCacheMu.Unlock()
	c.sessionKeyCache[sessionKeyCachePrefixResource+resourceID] = sessionKey
}

// GetSessionKeyByMetadataKeyID retrieves a cached session key by metadata key ID.
// These session keys are extracted during decrypt and cached as fallback.
// Returns a clone of the cached key to prevent callers from modifying the cache.
func (c *Client) GetSessionKeyByMetadataKeyID(metadataKeyID string) *crypto.SessionKey {
	c.sessionKeyCacheMu.RLock()
	defer c.sessionKeyCacheMu.RUnlock()
	return cloneSessionKey(c.sessionKeyCache[sessionKeyCachePrefixMetaKey+metadataKeyID])
}

// SetSessionKeyByMetadataKeyID stores a session key for a metadata key ID
func (c *Client) SetSessionKeyByMetadataKeyID(metadataKeyID string, sessionKey *crypto.SessionKey) {
	c.sessionKeyCacheMu.Lock()
	defer c.sessionKeyCacheMu.Unlock()
	c.sessionKeyCache[sessionKeyCachePrefixMetaKey+metadataKeyID] = sessionKey
}
