//go:build integration

package helper

import (
	"context"
	"testing"

	"github.com/passbolt/go-passbolt/api"
)

// TestSetupAccount_CompletesInviteFlow exercises helper.SetupAccount end-to-end:
// invite a fresh user via Passbolt's register_user command, complete the GPG
// setup, and verify the returned private key authenticates a real session.
// Restores the integration coverage lost when helper/setup_test.go was deleted.
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

	privKey, err := SetupAccount(ctx, regClient, userID, token, pass)
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
