//go:build integration

package helper

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/passbolt/go-passbolt/api"
	"github.com/passbolt/go-passbolt/internal/testenv"
)

// client is the authenticated SDK client shared by every integration test in
// this package. It is populated by TestMain from a fresh Passbolt container.
var client *api.Client

// pb is the running Passbolt instance exposed so individual tests can invite
// additional users (e.g. to exercise SetupAccount on a fresh invite).
var pb *testenv.Passbolt

// Email/password convention mirrors the existing Passbolt seed-data fixtures
// (password == email) so any test-script that hard-codes seeded emails like
// "ada@passbolt.com" or "adele@passbolt.com" lines up.
const (
	testAdminEmail    = "admin@passbolt.com"
	testAdminPassword = "admin@passbolt.com"
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
	pb, err = testenv.Start(ctx)
	if err != nil {
		return 0, fmt.Errorf("start testenv: %w", err)
	}
	defer func() { _ = pb.Close(context.Background()) }()

	admin, err := pb.CreateUser(ctx, testAdminEmail, "Admin", "Tester", "admin", testAdminPassword)
	if err != nil {
		return 0, fmt.Errorf("create admin: %w", err)
	}

	// V5 must be enabled before the test client logs in: settings are cached
	// per-client at Login, so toggling them afterwards leaves the cache stale.
	if err := pb.EnableV5Resources(ctx, admin); err != nil {
		return 0, fmt.Errorf("enable v5: %w", err)
	}

	c, err := api.NewClient(nil, "go-passbolt-helper-tests", pb.BaseURL, admin.PrivateKey, admin.Password)
	if err != nil {
		return 0, fmt.Errorf("new client: %w", err)
	}
	if err := c.Login(ctx); err != nil {
		return 0, fmt.Errorf("login: %w", err)
	}
	client = c

	return m.Run(), nil
}
