package helper

import (
	"context"
	"fmt"
	"strings"

	"github.com/passbolt/go-passbolt/api"
)

// ParseInviteUrl Parses a Passbolt Invite URL into a user id and token
func ParseInviteUrl(url string) (string, string, error) {
	split := strings.Split(url, "/")
	if len(split) < 4 {
		return "", "", fmt.Errorf("Invite URL does not have enough slashes")
	}
	return split[len(split)-2], strings.TrimSuffix(split[len(split)-1], ".json"), nil
}

// SetupAccount Setup a Account for a Invited User.
// (Use ParseInviteUrl to get the userid and token from a Invite URL)
func SetupAccount(ctx context.Context, c *api.Client, userID, token, password string) (string, error) {

	install, err := c.SetupInstall(ctx, userID, token)
	if err != nil {
		return "", fmt.Errorf("Get Setup Install Data: %w", err)
	}

	keyName := install.Profile.FirstName + " " + install.Profile.LastName + " " + install.Username

	pgp := c.GetPGPHandle()

	keyHandler := pgp.KeyGeneration().AddUserId(keyName, install.Username).New()

	key, err := keyHandler.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("Generating Private Key: %w", err)
	}

	defer key.ClearPrivateParams()

	publicKey, err := key.GetArmoredPublicKey()
	if err != nil {
		return "", fmt.Errorf("Get Public Key: %w", err)
	}

	lockedKey, err := pgp.LockKey(key, []byte(password))
	if err != nil {
		return "", fmt.Errorf("Locking Private Key: %w", err)
	}

	defer lockedKey.ClearPrivateParams()

	privateKey, err := lockedKey.Armor()
	if err != nil {
		return "", fmt.Errorf("Get Private Key: %w", err)
	}

	request := api.SetupCompleteRequest{
		AuthenticationToken: api.AuthenticationToken{
			Token: token,
		},
		User: api.User{
			Locale: api.UserLocaleENUK,
		},
		GPGKey: api.GPGKey{
			ArmoredKey: publicKey,
		},
	}

	err = c.SetupComplete(ctx, userID, request)
	if err != nil {
		return "", fmt.Errorf("Setup Completion Failed: %w", err)
	}
	return privateKey, nil
}
