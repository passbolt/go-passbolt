//go:build integration

package testenv_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/passbolt/go-passbolt/api"
	"github.com/passbolt/go-passbolt/internal/testenv"
)

// TestStartEndToEnd is a smoke test for the testenv package itself: bring up
// MariaDB + Passbolt, register an admin, enable V5, then sanity-check that the
// returned URL serves a Passbolt healthcheck and a real client can log in.
// Catches breakage in the container orchestration before it cascades into
// every package that uses testenv.
func TestStartEndToEnd(t *testing.T) {
	ctx := context.Background()

	pb, err := testenv.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = pb.Close(context.Background()) })

	if !strings.HasPrefix(pb.BaseURL, "http://") {
		t.Errorf("BaseURL = %q, want http:// prefix", pb.BaseURL)
	}

	resp, err := http.Get(pb.BaseURL + "/healthcheck/status.json")
	if err != nil {
		t.Fatalf("healthcheck GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthcheck status = %d, want 200", resp.StatusCode)
	}

	admin, err := pb.CreateUser(ctx, "smoke@passbolt.com", "Smoke", "Test", "admin", "smoke@passbolt.com")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if admin.PrivateKey == "" {
		t.Fatal("CreateUser returned empty private key")
	}

	if err := pb.EnableV5Resources(ctx, admin); err != nil {
		t.Fatalf("EnableV5Resources: %v", err)
	}

	c, err := api.NewClient(nil, "testenv-smoke", pb.BaseURL, admin.PrivateKey, admin.Password)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := c.Logout(ctx); err != nil {
		t.Errorf("Logout: %v", err)
	}
}
