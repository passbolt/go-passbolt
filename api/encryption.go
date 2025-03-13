package api

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// EncryptMessage encrypts a message using the users public key and then signes the message using the users private key
func (c *Client) EncryptMessage(message string) (string, error) {
	key, err := c.getPrivateKey(c.userPrivateKey, c.userPassword)
	if err != nil {
		return "", fmt.Errorf("Get Private Key: %w", err)
	}

	defer key.ClearPrivateParams()

	encHandle, err := c.pgp.Encryption().SigningKey(key).Recipient(key).New()
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
	key, err := c.getPrivateKey(c.userPrivateKey, c.userPassword)
	if err != nil {
		return "", fmt.Errorf("Get Private Key: %w", err)
	}

	defer key.ClearPrivateParams()

	publicKey, err := crypto.NewKeyFromArmored(publickey)
	if err != nil {
		return "", fmt.Errorf("Get Public Key: %w", err)
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

// DecryptMessage decrypts a message using the users Private Key
func (c *Client) DecryptMessage(message string) (string, error) {
	key, err := c.getPrivateKey(c.userPrivateKey, c.userPassword)
	if err != nil {
		return "", fmt.Errorf("Get Private Key: %w", err)
	}

	defer key.ClearPrivateParams()

	decHandle, err := c.pgp.Decryption().DecryptionKey(key).New()
	if err != nil {
		return "", fmt.Errorf("New Decryptor: %w", err)
	}

	defer decHandle.ClearPrivateParams()

	res, err := decHandle.Decrypt([]byte(message), crypto.Armor)
	if err != nil {
		return "", fmt.Errorf("Decrypt Message: %w", err)
	}

	// We cant Verify the signature as we don't store other users public keys locally and don't know which user did encrypt it
	//return helper.DecryptVerifyMessageArmored(c.userPublicKey, c.userPrivateKey, c.userPassword, message)

	return res.String(), nil
}

// TODO change []byte to string?
func (c *Client) DecryptMessageWithPrivateKey(privateKey string, passphrase []byte, ciphertextArmored string) (string, error) {
	key, err := c.getPrivateKey(privateKey, passphrase)
	if err != nil {
		return "", fmt.Errorf("Get Private Key: %w", err)
	}

	defer key.ClearPrivateParams()

	decHandle, err := c.pgp.Decryption().DecryptionKey(key).New()
	if err != nil {
		return "", fmt.Errorf("New Decryptor: %w", err)
	}

	defer decHandle.ClearPrivateParams()

	res, err := decHandle.Decrypt([]byte(ciphertextArmored), crypto.Armor)
	if err != nil {
		return "", fmt.Errorf("Decrypt: %w", err)
	}

	return string(res.Bytes()), nil
}

func (c *Client) getPrivateKey(privateKey string, passphrase []byte) (*crypto.Key, error) {
	if c.userPrivateKey == "" {
		return nil, fmt.Errorf("Client has no Private Key")
	}

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
