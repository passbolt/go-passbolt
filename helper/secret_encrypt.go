package helper

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/passbolt/go-passbolt/api"
)

// encryptForArmoredKey parses an armored public key and encrypts plaintext for
// that recipient.
//
// It captures the parse-then-encrypt step that is shared by the resource
// update, resource share and group update secret re-encryption loops. The
// surrounding logic (which recipients to encrypt for, own-key handling, secret
// caching and the resulting api.Secret shape) differs between those callers and
// stays local to each.
func encryptForArmoredKey(c *api.Client, armoredKey, plaintext string) (string, error) {
	publicKey, err := crypto.NewKeyFromArmored(armoredKey)
	if err != nil {
		return "", fmt.Errorf("parsing public key: %w", err)
	}

	encrypted, err := c.EncryptMessageWithKey(publicKey, plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypting secret: %w", err)
	}
	return encrypted, nil
}
