//go:build integration

// Integration test bootstrap for the api package's external test files
// (package api_test). Boots a fresh Passbolt + MariaDB via testcontainers,
// creates an admin user, enables V5 resources, and exposes the resulting
// URL + admin credentials to the test functions. Mirrors the pattern used by
// helper/integration_main_test.go.

package api_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/passbolt/go-passbolt/api"
	"github.com/passbolt/go-passbolt/internal/testenv"
)

const (
	testAdminEmail    = "admin@passbolt.com"
	testAdminPassword = "admin@passbolt.com"
)

// Populated by TestMain so individual tests can build a client without each
// re-running the testcontainers boot.
var (
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

	pb, err := testenv.Start(ctx)
	if err != nil {
		return 0, fmt.Errorf("start testenv: %w", err)
	}
	defer func() { _ = pb.Close(context.Background()) }()

	admin, err := pb.CreateUser(ctx, testAdminEmail, "Admin", "Tester", "admin", testAdminPassword)
	if err != nil {
		return 0, fmt.Errorf("create admin: %w", err)
	}

	if err := pb.EnableV5Resources(ctx, admin); err != nil {
		return 0, fmt.Errorf("enable v5: %w", err)
	}

	testServerURL = pb.BaseURL
	testAdminPrivKey = admin.PrivateKey

	return m.Run(), nil
}

// setupTestClient builds an authenticated client against the package-level
// Passbolt instance booted by TestMain. Shared by every test file in
// package api_test that needs a live server.
func setupTestClient(t *testing.T) (*api.Client, context.Context, func()) {
	t.Helper()
	client, err := api.NewClient(nil, "go-passbolt-test/1.0", testServerURL, testAdminPrivKey, testAdminPassword)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	cleanup := func() {
		// Surface a non-nil Logout error without failing the test: it
		// usually means the server-side session is already gone, which
		// is benign at teardown but worth a log line if it becomes
		// chronic.
		if err := client.Logout(ctx); err != nil {
			t.Logf("Logout (cleanup): %v", err)
		}
	}
	return client, ctx, cleanup
}
