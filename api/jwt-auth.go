package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type JWTLogin struct {
	UserID    string `json:"user_id"`
	Challenge string `json:"challenge"`
}

type JWTLoginChallenge struct {
	Version           string `json:"version"`
	Domain            string `json:"domain"`
	VerifyToken       string `json:"verify_token"`
	VerifyTokenExpiry int64  `json:"verify_token_expiry"`
}

type JWTLoginChallengeResult struct {
	Version      string `json:"version"`
	Domain       string `json:"domain"`
	VerifyToken  string `json:"verify_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (c *Client) LoginJWT(ctx context.Context) error {
	/*
		jwtKeyResult, _, err := c.DoCustomRequestAndReturnRawResponse(ctx, "POST", "/auth/jwt/jwks.json", "v2", nil, nil)
		if err != nil {
			return fmt.Errorf("Fetching JWT Server Key: %w", err)
		}*/

	serverGpgPublicKeyResponse, err := c.DoCustomRequest(ctx, "POST", "/auth/verify.json", "v2", nil, nil)
	if err != nil {
		return fmt.Errorf("Fetching GPG Server Key: %w", err)
	}

	var serverGpgPublicKey PublicKeyReponse
	err = json.Unmarshal(serverGpgPublicKeyResponse.Body, &serverGpgPublicKey)
	if err != nil {
		return fmt.Errorf("Parsing GPG Server Key JSON: %w", err)
	}

	verifyToken, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("Generating Verify Token: %w", err)
	}

	jwtLoginChallenge := JWTLoginChallenge{
		Version:           "1.0.0",
		Domain:            c.baseURL.String(),
		VerifyToken:       verifyToken.String(),
		VerifyTokenExpiry: time.Now().Add(2 * time.Minute).Unix(),
	}

	jwtLoginChallengeString, err := json.Marshal(jwtLoginChallenge)
	if err != nil {
		return fmt.Errorf("Marshalling jwtLoginChallenge: %w", err)
	}

	jwtLoginChallengeEncrypted, err := c.EncryptMessageWithPublicKey(serverGpgPublicKey.Keydata, string(jwtLoginChallengeString))
	if err != nil {
		return fmt.Errorf("Encypting and Signing JWT Login Challenge: %w", err)
	}

	loginPayload := JWTLogin{
		UserID:    c.userID, // where do i get this from
		Challenge: jwtLoginChallengeEncrypted,
	}

	loginResponse, err := c.DoCustomRequest(ctx, "POST", "/auth/jwt/login.json", "v2", loginPayload, nil)
	if err != nil {
		return fmt.Errorf("JWT Login: %w", err)
	}

	var jwtLoginResponse JWTLogin
	err = json.Unmarshal(loginResponse.Body, &jwtLoginResponse)
	if err != nil {
		return fmt.Errorf("Parsing Login Response: %w", err)
	}

	jetLoginChallengeResponseString, err := c.DecryptMessage(jwtLoginResponse.Challenge)
	if err != nil {
		return fmt.Errorf("Decrypting Login Challenge Response: %w", err)
	}

	var jwtLoginChallengeResult JWTLoginChallengeResult
	err = json.Unmarshal([]byte(jetLoginChallengeResponseString), &jwtLoginChallengeResult)
	if err != nil {
		return fmt.Errorf("Parsing Login Challange Response: %w", err)
	}

	// TODO Verify the Format of These all fields in jwtLoginChallengeResult

	if jwtLoginChallengeResult.VerifyToken != verifyToken.String() {
		return fmt.Errorf("Server Returned incorrect Verify Token: %v != %v", jwtLoginChallengeResult.VerifyToken, verifyToken.String())
	}

	// TODO verify JWT https://stackoverflow.com/questions/41077953/go-language-and-verify-jwt
	return nil
}
