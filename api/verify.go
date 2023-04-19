package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/google/uuid"
)

// GPGVerifyContainer is used for verification
type GPGVerifyContainer struct {
	Req GPGVerify `json:"gpg_auth"`
}

// GPGVerify is used for verification
type GPGVerify struct {
	KeyID string `json:"keyid"`
	Token string `json:"server_verify_token,omitempty"`
}

// SetupServerVerification sets up Server Verification, Only works before login
func (c *Client) SetupServerVerification(ctx context.Context) (string, string, error) {
	serverKey, _, err := c.GetPublicKey(ctx)
	if err != nil {
		return "", "", fmt.Errorf("Getting Server Key: %w", err)
	}
	uuid, err := uuid.NewRandom()
	if err != nil {
		return "", "", fmt.Errorf("Generating UUID: %w", err)
	}
	token := "gpgauthv1.3.0|36|" + uuid.String() + "|gpgauthv1.3.0"
	encToken, err := c.EncryptMessageWithPublicKey(serverKey, token)
	if err != nil {
		return "", "", fmt.Errorf("Encrypting Challenge: %w", err)
	}
	err = c.VerifyServer(ctx, token, encToken)
	if err != nil {
		return "", "", fmt.Errorf("Initial Verification: %w", err)
	}
	return token, encToken, err
}

// VerifyServer verifys that the Server is still the same one as during the Setup, Only works before login
func (c *Client) VerifyServer(ctx context.Context, token, encToken string) error {
	privateKeyObj, err := crypto.NewKeyFromArmored(c.userPrivateKey)
	if err != nil {
		return fmt.Errorf("Parsing User Private Key: %w", err)
	}

	data := GPGVerifyContainer{
		Req: GPGVerify{
			Token: encToken,
			KeyID: privateKeyObj.GetFingerprint(),
		},
	}
	raw, _, err := c.DoCustomRequestAndReturnRawResponse(ctx, "POST", "/auth/verify.json", "v2", data, nil)
	if err != nil && !strings.Contains(err.Error(), "The authentication failed.") {
		return fmt.Errorf("Sending Verification Challenge: %w", err)
	}

	if raw.Header.Get("X-GPGAuth-Verify-Response") != token {
		return fmt.Errorf("Server Response did not Match Saved Token")
	}
	return nil
}
