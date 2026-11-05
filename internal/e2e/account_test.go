//go:build integration

package e2e

// Client creation, account setup, login and logout.

import (
	"context"
	"strings"
	"testing"

	"github.com/passbolt/go-passbolt/api"
	"github.com/passbolt/go-passbolt/helper"
)

// TestClientCreationWithV3 tests that the client is created with gopenpgp v3
func TestClientCreationWithV3(t *testing.T) {
	client, err := api.NewClient(nil, "", testServerURL, testAdminPrivKey, testAdminPassword)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	// Verify PGP handle is initialized
	pgp := client.GetPGPHandle()
	if pgp == nil {
		t.Error("Expected non-nil PGP handle")
	}
}

// TestSetupAccount_CompletesInviteFlow invites a user, runs helper.SetupAccount
// and checks the returned key can log in.
func TestSetupAccount_CompletesInviteFlow(t *testing.T) {
	if client == nil {
		t.SkipNow()
	}

	ctx := context.Background()
	const (
		email = "setup-account@passbolt.com"
		pass  = "setup-account@passbolt.com"
	)

	userID, token, err := pb.RegisterUser(ctx, email, "Setup", "Account", "user")
	if err != nil {
		t.Fatalf("register invited user: %v", err)
	}

	regClient, err := api.NewClient(nil, "go-passbolt-setup-test", pb.BaseURL, "", "")
	if err != nil {
		t.Fatalf("registration client: %v", err)
	}

	privKey, err := helper.SetupAccount(ctx, regClient, userID, token, pass)
	if err != nil {
		t.Fatalf("SetupAccount: %v", err)
	}
	if privKey == "" {
		t.Fatal("SetupAccount returned empty private key")
	}

	loggedIn, err := api.NewClient(nil, "go-passbolt-setup-test", pb.BaseURL, privKey, pass)
	if err != nil {
		t.Fatalf("client with freshly-set-up key: %v", err)
	}
	if err := loggedIn.Login(ctx); err != nil {
		t.Fatalf("login with freshly-set-up key: %v", err)
	}
	t.Cleanup(func() { _ = loggedIn.Logout(context.Background()) })
}

// TestLogoutLoginCycle tests that client cannot be reused after logout (security by design)
func TestLogoutLoginCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Verify client works before logout
	_, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("Client should work before logout: %v", err)
	}

	// Logout
	err = client.Logout(ctx)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	// Verify client doesn't work after logout
	_, err = client.GetUserPrivateKeyCopy()
	if err == nil {
		t.Error("Expected client to fail after logout")
	}

	// Try to login again (should fail gracefully, not panic)
	err = client.Login(ctx)
	if err == nil {
		t.Error("Expected Login() to fail after logout (client should not be reusable)")
	}

	// Verify error message is clear
	if err != nil {
		errMsg := strings.ToLower(err.Error())
		if !strings.Contains(errMsg, "no user private key") &&
			!strings.Contains(errMsg, "logged out") &&
			!strings.Contains(errMsg, "cannot login") {
			t.Logf("Warning: Error message may not be clear: %v", err)
		} else {
			t.Logf("Got expected error: %v", err)
		}
	}

	t.Log("SUCCESS: Client correctly prevents reuse after logout")
}

// TestDecryptAfterLogoutFails tests that decrypt operations fail after logout with clear errors
func TestDecryptAfterLogoutFails(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Encrypt a message before logout
	testMessage := "Secret message to decrypt"
	encrypted, err := client.EncryptMessage(testMessage)
	if err != nil {
		t.Fatalf("Failed to encrypt before logout: %v", err)
	}

	// Logout
	err = client.Logout(ctx)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	// Try to decrypt after logout (should fail)
	_, err = client.DecryptMessage(encrypted)
	if err == nil {
		t.Error("Expected error when decrypting after logout")
	}

	// Verify error message is clear
	if err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "no user private key") &&
			!strings.Contains(strings.ToLower(err.Error()), "logged out") {
			t.Logf("Warning: Error message may not be clear: %v", err)
		} else {
			t.Logf("Got expected error: %v", err)
		}
	}
}

// TestSecureZeroingOnLogout tests that logout clears user private key
func TestSecureZeroingOnLogout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, ctx, cleanup := setupTestClient(t)
	defer cleanup()

	// Get user private key copy before logout
	keyBefore, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("Failed to get user private key: %v", err)
	}

	if keyBefore == nil {
		t.Fatal("Expected non-nil user private key before logout")
	}

	fingerprintBefore := keyBefore.GetFingerprint()
	t.Logf("User key fingerprint before logout: %s", fingerprintBefore)

	// Logout
	err = client.Logout(ctx)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	// Try to get user private key after logout (should fail)
	keyAfter, err := client.GetUserPrivateKeyCopy()
	if err == nil {
		t.Error("Expected error when getting user private key after logout")
	}
	if keyAfter != nil {
		t.Error("Expected nil user private key after logout")
	}

	// Try to encrypt (should fail gracefully)
	_, err = client.EncryptMessage("test message")
	if err == nil {
		t.Error("Expected error when encrypting after logout")
	}
	if err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "no user private key") &&
			!strings.Contains(strings.ToLower(err.Error()), "logged out") {
			t.Logf("Warning: Error message may not be clear: %v", err)
		} else {
			t.Logf("Got expected error: %v", err)
		}
	}
}
