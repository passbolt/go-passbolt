package api

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/helper"
)

// EncryptMessage encrypts a message using the users public key and then signes the message using the users private key
func (c *Client) EncryptMessage(message string) (string, error) {
	if c.userPrivateKey == "" {
		return "", fmt.Errorf("Client has no Private Key")
	} else if c.userPublicKey == "" {
		return "", fmt.Errorf("Client has no Public Key")
	}
	return helper.EncryptSignMessageArmored(c.userPublicKey, c.userPrivateKey, c.userPassword, message)
}

// EncryptMessageWithPublicKey encrypts a message using the provided public key and then signes the message using the users private key
func (c *Client) EncryptMessageWithPublicKey(publickey, message string) (string, error) {
	if c.userPrivateKey == "" {
		return "", fmt.Errorf("Client has no Private Key")
	}
	return helper.EncryptSignMessageArmored(publickey, c.userPrivateKey, c.userPassword, message)
}

// DecryptMessage decrypts a message using the users Private Key
func (c *Client) DecryptMessage(message string) (string, error) {
	if c.userPrivateKey == "" {
		return "", fmt.Errorf("Client has no Private Key")
	}
	// We cant Verify the signature as we don't store other users public keys locally and don't know which user did encrypt it
	//return helper.DecryptVerifyMessageArmored(c.userPublicKey, c.userPrivateKey, c.userPassword, message)
	return helper.DecryptMessageArmored(c.userPrivateKey, c.userPassword, message)
}
