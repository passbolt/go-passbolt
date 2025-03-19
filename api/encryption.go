package api

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// EncryptMessage encrypts a message using the users public key and then signes the message using the users private key
func (c *Client) EncryptMessage(message string) (string, error) {
	encHandle, err := c.pgp.Encryption().SigningKey(c.userPrivateKey).Recipient(c.userPrivateKey).New()
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
func (c *Client) EncryptMessageWithPublicKey(publickey, message string) (string, error) {
	publicKey, err := crypto.NewKeyFromArmored(publickey)
	if err != nil {
		return "", fmt.Errorf("Get Public Key: %w", err)
	}

	encHandle, err := c.pgp.Encryption().SigningKey(c.userPrivateKey).Recipient(publicKey).New()
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

// DecryptMessage decrypts a message using the users Private Key
func (c *Client) DecryptMessage(armoredCiphertext string) (string, error) {
	message, _, err := c.DecryptMessageWithPrivateKeyAndReturnSessionKey(c.userPrivateKey, armoredCiphertext)
	return message, err
}

// DecryptMessageWithPrivateKey Decrypts a Message using the Provided Private Key
// Returns the Session key so that it can be saved in a cache
func (c *Client) DecryptMessageWithPrivateKeyAndReturnSessionKey(privateKey *crypto.Key, armoredCiphertext string) (string, *crypto.SessionKey, error) {

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

	return res.String(), res.SessionKey(), nil
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
