package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

type MetadataKeyType string

const (
	MetadataKeyTypeUserKey   MetadataKeyType = "user_key"
	MetadataKeyTypeSharedKey MetadataKeyType = "shared_key"
)

func (s MetadataKeyType) IsValid() bool {
	switch s {
	case MetadataKeyTypeUserKey, MetadataKeyTypeSharedKey:
		return true
	}
	return false
}

// MetadataKey is a MetadataKey
type MetadataKey struct {
	ID          string `json:"id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ArmoredKey  string `json:"armored_key,omitempty"`
	Created     Time   `json:"created,omitempty"`
	Modified    Time   `json:"modified,omitempty"`

	// These are always null? Used for Key Rotation?
	//"expired": null,
	//"deleted": null,

	CreatedBy  *string `json:"created_by,omitempty"`
	ModifiedBy *string `json:"modified_by,omitempty"`

	MetadataPrivateKeys []MetadataPrivateKey `json:"metadata_private_keys,omitempty"`
}

// MetadataPrivateKey is a MetadataPrivateKey
type MetadataPrivateKey struct {
	ID                      string  `json:"id,omitempty"`
	MetadataKeyID           string  `json:"metadata_key_id,omitempty"`
	UserID                  *string `json:"user_id,omitempty"` // TODO, is this nullable. The Docs says yes and no
	Data                    string  `json:"data,omitempty"`
	Created                 Time    `json:"created,omitempty"`
	Modified                Time    `json:"modified,omitempty"`
	CreatedBy               *string `json:"created_by,omitempty"`
	ModifiedBy              *string `json:"modified_by,omitempty"`
	DataSignedByCurrentUser *Time   `json:"data_signed_by_current_user,omitempty"`
}

// MetadataPrivateKeyData is a MetadataPrivateKeyData
type MetadataPrivateKeyData struct {
	// ObjectType Must always be PASSBOLT_METADATA_PRIVATE_KEY
	ObjectType string `json:"object_type,omitempty"`
	// Domain Must be the Passbolt Server URL
	Domain      string `json:"domain,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ArmoredKey  string `json:"armored_key,omitempty"`
	// Passphrase must be Empty for Server Keys
	Passphrase string `json:"passphrase,omitempty"`
	// When this key was Signed by our User for Trusting new keys which where trusted on other Devices
	Signed Time `json:"signed,omitempty"`
}

// GetMetadataKeysOptions are all available query parameters
type GetMetadataKeysOptions struct {
	FilterDeleted bool `url:"filter[deleted],omitempty"`
	FilterExpired bool `url:"filter[expired],omitempty"`

	ContainMetadataPrivateKeys bool `url:"contain[metadata_private_keys],omitempty"`
}

// SetTrustedMetadatakeyFingerprint sets the trusted metadata key fingerprint.
func (c *Client) SetTrustedMetadatakeyFingerprint(fingerprint string, signTime time.Time) {
	c.trustedMetadataKeyFingerprint = &fingerprint
}

// GetTrustedMetadatakeyFingerprint returns the trusted metadata key fingerprint.
func (c *Client) GetTrustedMetadatakeyFingerprint() *string {
	return c.trustedMetadataKeyFingerprint
}

// GetMetadataKeys gets all Passbolt GetMetadataKeys
func (c *Client) GetMetadataKeys(ctx context.Context, opts *GetMetadataKeysOptions) ([]MetadataKey, error) {
	msg, err := c.DoCustomRequestV5(ctx, "GET", "/metadata/keys.json", nil, opts)
	if err != nil {
		return nil, err
	}

	var metadataKeys []MetadataKey
	err = json.Unmarshal(msg.Body, &metadataKeys)
	if err != nil {
		return nil, err
	}
	return metadataKeys, nil
}

// GetMetadataKey gets a Metadata key, Personal indicates if the function should return the personal key,
// If personal keys have been disabled on the server then we return the shared key
// Returns the Key ID, Key Type and the Key itself
func (c *Client) GetMetadataKey(ctx context.Context, personal bool) (string, MetadataKeyType, *crypto.Key, error) {
	// if personal is requsted and it is allowed by the server, then return that
	if personal && c.MetadataKeySettings().AllowUsageOfPersonalKeys {
		key, err := c.GetUserPrivateKeyCopy()
		if err != nil {
			return "", "", nil, fmt.Errorf("get User Private Key: %w", err)
		}

		me, err := c.GetMe(ctx)
		if err != nil {
			return "", "", nil, fmt.Errorf("get User Me: %w", err)
		}

		if me.GPGKey == nil {
			return "", "", nil, fmt.Errorf("user Me GPG Key nil")
		}

		return me.GPGKey.ID, MetadataKeyTypeUserKey, key, nil
	}

	keys, err := c.GetMetadataKeys(ctx, &GetMetadataKeysOptions{
		ContainMetadataPrivateKeys: true,
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("get Metadata Key: %w", err)
	}

	// Get The Newest Metadata Key
	metadatakey := keys[len(keys)-1]
	var privateMetadataKey *MetadataPrivateKey = nil
	for _, _privateMetadataKey := range metadatakey.MetadataPrivateKeys {
		if *_privateMetadataKey.UserID == c.userID {
			privateMetadataKey = &_privateMetadataKey
			c.log("Found privateMetadataKey for our user %v", _privateMetadataKey.ID)
			break
		}
	}

	if privateMetadataKey == nil {
		return "", "", nil, fmt.Errorf("no Metadata Private key for our user")
	}

	decPrivateMetadatakey, err := c.DecryptMessage(privateMetadataKey.Data)
	if err != nil {
		return "", "", nil, fmt.Errorf("decrypt Metadata Private Key Data: %w", err)
	}

	var data MetadataPrivateKeyData
	err = json.Unmarshal([]byte(decPrivateMetadatakey), &data)
	if err != nil {
		return "", "", nil, fmt.Errorf("parse Metadata Private Key Data")
	}

	metadataPrivateKeyObj, err := GetPrivateKeyFromArmor(data.ArmoredKey, []byte(data.Passphrase))
	if err != nil {
		return "", "", nil, fmt.Errorf("get Metadata Private Key: %w", err)
	}

	// Verify the key
	if c.GetTrustedMetadatakeyFingerprint() == nil || metadataPrivateKeyObj.GetFingerprint() != *c.GetTrustedMetadatakeyFingerprint() {

		if c.trustedMetadataKeySigntime != nil && !data.Signed.After(*c.trustedMetadataKeySigntime) {
			return "", "", nil, fmt.Errorf("new Metadata Key is older than the currently trusted one: %w", err)
		}

		userPrivateKey, err := c.GetUserPrivateKeyCopy()
		if err != nil {
			return "", "", nil, fmt.Errorf("get User Private Key Copy: %w", err)
		}

		verify, err := c.pgp.Verify().VerificationKey(userPrivateKey).New()
		if err != nil {
			return "", "", nil, fmt.Errorf("creating verifier: %w", err)
		}
		verifyRes, err := verify.VerifyInline([]byte(privateMetadataKey.Data), crypto.Armor)
		if err != nil {
			return "", "", nil, fmt.Errorf("verify User Metadata Private Key Signature: %w", err)
		}

		signedByFingerprint := hex.EncodeToString(verifyRes.SignedByFingerprint())
		c.log("Metadata Private key Signed by %v", signedByFingerprint)
		c.log("User key Fingerprint %v", userPrivateKey.GetFingerprint())

		// Check if the Metadata Private Key was signed by our User Private key
		trusted := false
		if signedByFingerprint == userPrivateKey.GetFingerprint() {
			trusted = true
			c.log("New Metadata Private Key has been signed by our Private key")
		} else {
			c.log("New Metadata Private Key has failed the signature check")
		}

		// Callback not Defined
		if c.MetadataKeyUpdatedCallback == nil {
			// Fail if there is a key pinned but the signature check failed
			if c.trustedMetadataKeyFingerprint != nil || !trusted {
				return "", "", nil, fmt.Errorf("metadata Key has changed, The Callback is nil, There is a Key Pinned but the new one is not trusted")
			}
			c.log("No Callback is defined, No Metadata key is pinned and the Signature is by our Private key, automatically trusting")

		} else {
			err = c.MetadataKeyUpdatedCallback(ctx, trusted, metadataPrivateKeyObj.GetFingerprint(), data.Signed.Time)
			if err != nil {
				return "", "", nil, fmt.Errorf("metadata Key has changed, Callback: %w", err)
			}
		}

		// Callback has not Returned an error, Thus the New Key has been accepted
		c.SetTrustedMetadatakeyFingerprint(metadataPrivateKeyObj.GetFingerprint(), data.Signed.Time)
	}

	return metadatakey.ID, MetadataKeyTypeSharedKey, metadataPrivateKeyObj, nil
}

// GetMetadataKeyByID is for fetching a specific metadatakey if needed for decryption, these are not verified.
func (c *Client) GetMetadataKeyByID(ctx context.Context, id string) (*crypto.Key, error) {
	keys, err := c.GetMetadataKeys(ctx, &GetMetadataKeysOptions{
		ContainMetadataPrivateKeys: true,
	})
	if err != nil {
		return nil, fmt.Errorf("get Metadata Key: %w", err)
	}
	var key *MetadataKey
	for _, k := range keys {
		if k.ID == id {
			key = &k
			break
		}
	}

	if key == nil {
		return nil, fmt.Errorf("metadata key not found: %v", id)
	}

	if len(key.MetadataPrivateKeys) == 0 {
		return nil, fmt.Errorf("no Metadata Private key for our user")
	}

	if len(key.MetadataPrivateKeys) > 1 {
		return nil, fmt.Errorf("more than 1 metadata Private key for our user")
	}

	var privMetdata = key.MetadataPrivateKeys[0]
	if *privMetdata.UserID != c.GetUserID() {
		return nil, fmt.Errorf("metadataPrivateKey is not for our user id: %v", privMetdata.UserID)
	}

	decPrivMetadatakey, err := c.DecryptMessage(privMetdata.Data)
	if err != nil {
		return nil, fmt.Errorf("decrypt Metadata Private Key Data: %w", err)
	}

	var data MetadataPrivateKeyData
	err = json.Unmarshal([]byte(decPrivMetadatakey), &data)
	if err != nil {
		return nil, fmt.Errorf("parse Metadata Private Key Data")
	}

	metadataPrivateKeyObj, err := GetPrivateKeyFromArmor(data.ArmoredKey, []byte(data.Passphrase))
	if err != nil {
		return nil, fmt.Errorf("get Metadata Private Key: %w", err)
	}

	return metadataPrivateKeyObj, nil
}
