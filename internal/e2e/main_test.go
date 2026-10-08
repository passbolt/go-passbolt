//go:build integration

package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/passbolt/go-passbolt/api"
	"github.com/passbolt/go-passbolt/internal/e2e/server"
)

// Passwords equal emails.
const (
	testAdminEmail    = "admin@passbolt.com"
	testAdminPassword = "admin@passbolt.com"
)

// Set by TestMain.
var (
	pb               *server.Passbolt
	client           *api.Client // logged in as admin, shared by all tests
	testServerURL    string
	testAdminPrivKey string
)

func TestMain(m *testing.M) {
	code, err := run(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "integration TestMain:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func run(m *testing.M) (int, error) {
	ctx := context.Background()

	var err error
	pb, err = server.Start(ctx)
	if err != nil {
		return 0, fmt.Errorf("start passbolt: %w", err)
	}
	defer func() { _ = pb.Close(context.Background()) }()

	admin, err := pb.CreateUser(ctx, testAdminEmail, "Admin", "Tester", "admin", testAdminPassword)
	if err != nil {
		return 0, fmt.Errorf("create admin: %w", err)
	}

	// Before any login: clients cache these settings at Login.
	if err := pb.EnableV5Resources(ctx, admin); err != nil {
		return 0, fmt.Errorf("enable v5: %w", err)
	}

	testServerURL = pb.BaseURL
	testAdminPrivKey = admin.PrivateKey

	client, err = api.NewClient(nil, "go-passbolt-tests", pb.BaseURL, admin.PrivateKey, admin.Password)
	if err != nil {
		return 0, fmt.Errorf("new client: %w", err)
	}
	if err := client.Login(ctx); err != nil {
		return 0, fmt.Errorf("login: %w", err)
	}

	return m.Run(), nil
}

// setupTestClient returns a new client logged in as admin, for tests that
// need their own session. Call the returned func to log out.
func setupTestClient(t *testing.T) (*api.Client, context.Context, func()) {
	t.Helper()
	c, err := api.NewClient(nil, "go-passbolt-test/1.0", testServerURL, testAdminPrivKey, testAdminPassword)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	cleanup := func() {
		if err := c.Logout(ctx); err != nil {
			t.Logf("Logout (cleanup): %v", err)
		}
	}
	return c, ctx, cleanup
}
