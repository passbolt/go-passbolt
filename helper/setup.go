package helper

import (
	"context"
	"fmt"
	"strings"

	"github.com/speatzle/go-passbolt/api"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

// SetupAccount Setup a Account for a Invited User
func SetupAccount(ctx context.Context, c *api.Client, inviteURL, password string) (string, error) {
	split := strings.Split(inviteURL, "/")
	if len(split) < 4 {
		return "", fmt.Errorf("Invite URL does not have enough slashes")
	}
	userID := split[len(split)-2]
	token := strings.TrimSuffix(split[len(split)-1], ".json")

	install, err := c.SetupInstall(ctx, userID, token)
	if err != nil {
		return "", fmt.Errorf("Get Setup Install Data: %w", err)
	}

	keyName := install.Profile.FirstName + " " + install.Profile.LastName + " <" + install.Username + ">"

	privateKey, err := helper.GenerateKey(keyName, install.Username, []byte(password), "rsa", 2048)
	if err != nil {
		return "", fmt.Errorf("Generating Private Key: %w", err)
	}

	key, err := crypto.NewKeyFromArmoredReader(strings.NewReader(privateKey))
	if err != nil {
		return "", fmt.Errorf("Reading Private Key: %w", err)
	}

	publicKey, err := key.GetArmoredPublicKey()
	if err != nil {
		return "", fmt.Errorf("Get Public Key: %w", err)
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
