package helper

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/passbolt/go-passbolt/api"
)

// GetMetadataKey gets a Metadata key, Personal indicates if the function should return the personal key,
// If personal keys have been disabled on the server then we return the shared key
// Returns the Key ID, Key Type and the Key itself
func GetMetadataKey(ctx context.Context, c *api.Client, personal bool) (string, api.MetadataKeyType, *crypto.Key, error) {
	// if personal is requsted and it is allowed by the server, then return that
	if personal && c.MetadataKeySettings().AllowUsageOfPersonalKeys {
		key, err := c.GetUserPrivateKeyCopy()
		if err != nil {
			return "", "", nil, fmt.Errorf("Get User Private Key: %w", err)
		}

		me, err := c.GetMe(ctx)
		if err != nil {
			return "", "", nil, fmt.Errorf("Get User Me: %w", err)
		}

		if me.GPGKey == nil {
			return "", "", nil, fmt.Errorf("User Me GPG Key nil")
		}

		return me.GPGKey.ID, api.MetadataKeyTypeUserKey, key, nil
	}

	keys, err := c.GetMetadataKeys(ctx, &api.GetMetadataKeysOptions{
		ContainMetadataPrivateKeys: true,
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("Get Metadata Key: %w", err)
	}

	// TODO Get Key by id?
	if len(keys) != 1 {
		return "", "", nil, fmt.Errorf("Not Exactly One Metadatakey Available")
	}

	if len(keys[0].MetadataPrivateKeys) == 0 {
		return "", "", nil, fmt.Errorf("No Metadata Private key for our user")
	}

	if len(keys[0].MetadataPrivateKeys) > 1 {
		return "", "", nil, fmt.Errorf("More than 1 metadata Private key for our user")
	}

	var privMetdata api.MetadataPrivateKey = keys[0].MetadataPrivateKeys[0]
	if *privMetdata.UserID != c.GetUserID() {
		return "", "", nil, fmt.Errorf("MetadataPrivateKey is not for our user id: %v", privMetdata.UserID)
	}

	decPrivMetadatakey, err := c.DecryptMessage(privMetdata.Data)
	if err != nil {
		return "", "", nil, fmt.Errorf("Decrypt Metadata Private Key Data: %w", err)
	}

	var data api.MetadataPrivateKeyData
	err = json.Unmarshal([]byte(decPrivMetadatakey), &data)
	if err != nil {
		return "", "", nil, fmt.Errorf("Parse Metadata Private Key Data")
	}

	metadataPrivateKeyObj, err := api.GetPrivateKeyFromArmor(data.ArmoredKey, []byte(data.Passphrase))
	if err != nil {
		return "", "", nil, fmt.Errorf("Get Metadata Private Key: %w", err)
	}

	return keys[0].ID, api.MetadataKeyTypeSharedKey, metadataPrivateKeyObj, nil
}

// GetMetadataKeyById is for fetching a specific metadatakey if needed for Decryption
func GetMetadataKeyById(ctx context.Context, c *api.Client, id string) (*crypto.Key, error) {
	keys, err := c.GetMetadataKeys(ctx, &api.GetMetadataKeysOptions{
		ContainMetadataPrivateKeys: true,
	})
	if err != nil {
		return nil, fmt.Errorf("Get Metadata Key: %w", err)
	}
	var key *api.MetadataKey
	for _, k := range keys {
		if k.ID == id {
			key = &k
			break
		}
	}

	if key == nil {
		return nil, fmt.Errorf("Metadata key not found: %v", id)
	}

	if len(key.MetadataPrivateKeys) == 0 {
		return nil, fmt.Errorf("No Metadata Private key for our user")
	}

	if len(key.MetadataPrivateKeys) > 1 {
		return nil, fmt.Errorf("More than 1 metadata Private key for our user")
	}

	var privMetdata api.MetadataPrivateKey = key.MetadataPrivateKeys[0]
	if *privMetdata.UserID != c.GetUserID() {
		return nil, fmt.Errorf("MetadataPrivateKey is not for our user id: %v", privMetdata.UserID)
	}

	decPrivMetadatakey, err := c.DecryptMessage(privMetdata.Data)
	if err != nil {
		return nil, fmt.Errorf("Decrypt Metadata Private Key Data: %w", err)
	}

	var data api.MetadataPrivateKeyData
	err = json.Unmarshal([]byte(decPrivMetadatakey), &data)
	if err != nil {
		return nil, fmt.Errorf("Parse Metadata Private Key Data")
	}

	metadataPrivateKeyObj, err := api.GetPrivateKeyFromArmor(data.ArmoredKey, []byte(data.Passphrase))
	if err != nil {
		return nil, fmt.Errorf("Get Metadata Private Key: %w", err)
	}

	return metadataPrivateKeyObj, nil
}
