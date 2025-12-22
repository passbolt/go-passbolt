package api

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// EncryptMessage encrypts a message using the users public key and then signes the message using the users private key.
// This method is thread-safe.
func (c *Client) EncryptMessage(message string) (string, error) {
	c.cryptoMu.RLock()
	defer c.cryptoMu.RUnlock()

	if c.userPrivateKey == nil {
		return "", fmt.Errorf("Client has no user private key (logged out or not initialized)")
	}

	key, err := c.userPrivateKey.Copy()
	if err != nil {
		return "", fmt.Errorf("Get Private Key Copy: %w", err)
	}

	encHandle, err := c.pgp.Encryption().SigningKey(key).Recipient(c.userPrivateKey).New()
	if err != nil {
		return "", fmt.Errorf("New Encryptor: %w", err)
	}

	defer encHandle.ClearPrivateParams()

	encMessage, err := encHandle.Encrypt([]byte(message))
	if err != nil {
		return "", fmt.Errorf("Encrypt Message: %w", err)
	}

	encArmor, err := encMessage.Armor()
	if err != nil {
		return "", fmt.Errorf("Armor Message: %w", err)
	}
	return encArmor, nil
}

// EncryptMessageWithPublicKey encrypts a message using the provided public key and then signes the message using the users private key
//
// Deprecated: EncryptMessageWithPublicKey is deprecated. Use EncryptMessageWithKey instead
func (c *Client) EncryptMessageWithPublicKey(publickey, message string) (string, error) {
	publicKey, err := crypto.NewKeyFromArmored(publickey)
	if err != nil {
		return "", fmt.Errorf("Get Public Key: %w", err)
	}

	return c.EncryptMessageWithKey(publicKey, message)
}

// EncryptMessageWithKey encrypts a message using the provided key and then signes the message using the users private key.
// This method is thread-safe.
func (c *Client) EncryptMessageWithKey(publicKey *crypto.Key, message string) (string, error) {
	c.cryptoMu.RLock()
	defer c.cryptoMu.RUnlock()

	if c.userPrivateKey == nil {
		return "", fmt.Errorf("Client has no user private key (logged out or not initialized)")
	}

	key, err := c.userPrivateKey.Copy()
	if err != nil {
		return "", fmt.Errorf("Get Private Key Copy: %w", err)
	}

	encHandle, err := c.pgp.Encryption().SigningKey(key).Recipient(publicKey).New()
	if err != nil {
		return "", fmt.Errorf("New Encryptor: %w", err)
	}

	defer encHandle.ClearPrivateParams()

	encMessage, err := encHandle.Encrypt([]byte(message))
	if err != nil {
		return "", fmt.Errorf("Encrypt Message: %w", err)
	}

	encArmor, err := encMessage.Armor()
	if err != nil {
		return "", fmt.Errorf("Armor Message: %w", err)
	}
	return encArmor, nil
}

// DecryptMessage decrypts a message using the users Private Key.
// This method is thread-safe.
func (c *Client) DecryptMessage(armoredCiphertext string) (string, error) {
	c.cryptoMu.RLock()
	defer c.cryptoMu.RUnlock()

	if c.userPrivateKey == nil {
		return "", fmt.Errorf("Client has no user private key (logged out or not initialized)")
	}

	key, err := c.userPrivateKey.Copy()
	if err != nil {
		return "", fmt.Errorf("Get Private Key Copy: %w", err)
	}

	message, _, err := c.decryptMessageWithPrivateKeyAndReturnSessionKeyLocked(key, armoredCiphertext)
	return message, err
}

// DecryptSecretWithResourceID decrypts a secret using the user's private key.
// Secrets are always encrypted per-user, so no session key caching is needed.
// Session key caching is only used for metadata decryption (shared metadata keys).
func (c *Client) DecryptSecretWithResourceID(resourceID string, armoredCiphertext string) (string, error) {
	// resourceID is kept for API compatibility but not used for caching
	// Secrets don't benefit from session key caching as they're per-user encrypted
	return c.DecryptMessage(armoredCiphertext)
}

// DecryptMessageWithPrivateKeyAndReturnSessionKey decrypts a message using the provided private key.
// Returns the session key so that it can be saved in a cache.
// This method is thread-safe.
func (c *Client) DecryptMessageWithPrivateKeyAndReturnSessionKey(privateKey *crypto.Key, armoredCiphertext string) (string, *crypto.SessionKey, error) {
	c.cryptoMu.RLock()
	defer c.cryptoMu.RUnlock()

	return c.decryptMessageWithPrivateKeyAndReturnSessionKeyLocked(privateKey, armoredCiphertext)
}

// decryptMessageWithPrivateKeyAndReturnSessionKeyLocked is the internal implementation.
// Caller must hold cryptoMu.RLock().
func (c *Client) decryptMessageWithPrivateKeyAndReturnSessionKeyLocked(privateKey *crypto.Key, armoredCiphertext string) (string, *crypto.SessionKey, error) {
	// Copy the private key to avoid it being cleared by ClearPrivateParams.
	// Note: The caller must ensure privateKey is not accessed concurrently
	// (either by passing a copy or by external synchronization).
	keyCopy, err := privateKey.Copy()
	if err != nil {
		return "", nil, fmt.Errorf("Copy Private Key: %w", err)
	}

	return c.decryptMessageWithPrivateKeyDirect(keyCopy, armoredCiphertext)
}

// decryptMessageWithPrivateKeyDirect performs decryption using the provided key directly.
// The key is used as-is without copying. The caller is responsible for ensuring the key
// is either a copy or not accessed concurrently.
// This is used when the key has already been copied under mutex protection.
func (c *Client) decryptMessageWithPrivateKeyDirect(privateKey *crypto.Key, armoredCiphertext string) (string, *crypto.SessionKey, error) {
	decHandle, err := c.pgp.Decryption().
		DecryptionKey(privateKey).
		RetrieveSessionKey().
		New()
	if err != nil {
		return "", nil, fmt.Errorf("New Decryptor: %w", err)
	}

	defer decHandle.ClearPrivateParams()

	res, err := decHandle.Decrypt([]byte(armoredCiphertext), crypto.Armor)
	if err != nil {
		return "", nil, fmt.Errorf("Decrypt: %w", err)
	}

	// Clone the session key before returning it, as ClearPrivateParams() will zero it out
	sessionKey := res.SessionKey()
	if sessionKey != nil {
		sessionKey = crypto.NewSessionKeyFromToken(sessionKey.Key, sessionKey.Algo)
	}

	return res.String(), sessionKey, nil
}

func GetPrivateKeyFromArmor(privateKey string, passphrase []byte) (*crypto.Key, error) {
	key, err := crypto.NewKeyFromArmored(privateKey)
	if err != nil {
		return nil, fmt.Errorf("Key From Armored: %w", err)
	}

	locked, err := key.IsLocked()
	if err != nil {
		return nil, fmt.Errorf("Is Key Locked: %w", err)
	}

	if locked {
		unlocked, err := key.Unlock(passphrase)
		if err != nil {
			return nil, fmt.Errorf("Unlock Key: %w", err)
		}
		return unlocked, nil
	}
	return key, nil
}

// DecryptMessageWithSessionKey Decrypts a Message using the Provided Session Key
func (c *Client) DecryptMessageWithSessionKey(sessionKey *crypto.SessionKey, ciphertextArmored string) (string, error) {
	decHandle, err := c.pgp.Decryption().SessionKey(sessionKey).New()
	if err != nil {
		return "", fmt.Errorf("New Decryptor: %w", err)
	}

	defer decHandle.ClearPrivateParams()

	res, err := decHandle.Decrypt([]byte(ciphertextArmored), crypto.Armor)
	if err != nil {
		return "", fmt.Errorf("Decrypt: %w", err)
	}

	return res.String(), nil
}

// GetUserPrivateKeyCopy returns a copy of the user's private key.
// This method is thread-safe.
func (c *Client) GetUserPrivateKeyCopy() (*crypto.Key, error) {
	c.cryptoMu.RLock()
	defer c.cryptoMu.RUnlock()

	if c.userPrivateKey == nil {
		return nil, fmt.Errorf("Client has no user private key (logged out or not initialized)")
	}

	key, err := c.userPrivateKey.Copy()
	if err != nil {
		return nil, fmt.Errorf("Get Private Key Copy: %w", err)
	}
	return key, nil
}
