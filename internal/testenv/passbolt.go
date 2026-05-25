// Package testenv provisions an ephemeral Passbolt + MariaDB stack via
// testcontainers-go so integration tests can talk to a fully-functional
// server without any external setup.
//
// Sync note: this file is duplicated at go-passbolt-cli/internal/testenv/
// passbolt.go. The duplication is intentional so the CLI's standalone CI can
// compile its integration tests without depending on an unreleased SDK
// package. When changing one copy, mirror the change in the other and verify
// with:
//
//	diff <repo>/go-passbolt/internal/testenv/passbolt.go \
//	     <repo>/go-passbolt-cli/internal/testenv/passbolt.go
package testenv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/passbolt/go-passbolt/api"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	mariadbImage  = "mariadb:10.11"
	passboltImage = "passbolt/passbolt:latest-ce"
)

// Credentials is everything a test needs to authenticate as a Passbolt user.
type Credentials struct {
	UserID     string
	Email      string
	Password   string
	PrivateKey string // ASCII-armored, locked with Password.
}

// Passbolt is a running Passbolt instance.
type Passbolt struct {
	BaseURL   string
	container testcontainers.Container
	teardown  []func(context.Context) error
}

// Close terminates every container/network the stack owns. Safe to call more
// than once. Errors are joined so that one failed teardown doesn't mask the
// others.
func (p *Passbolt) Close(ctx context.Context) error {
	var errs []error
	for i := len(p.teardown) - 1; i >= 0; i-- {
		if err := p.teardown[i](ctx); err != nil {
			errs = append(errs, err)
		}
	}
	p.teardown = nil
	return errors.Join(errs...)
}

// Start brings up MariaDB + Passbolt on a shared Docker network. The caller
// owns teardown via (*Passbolt).Close. Use StartT from a test function if you
// want automatic t.Cleanup wiring. Cold start is ~30-60s once images are
// cached.
func Start(ctx context.Context) (*Passbolt, error) {
	p := &Passbolt{}
	rollback := func(err error) (*Passbolt, error) {
		_ = p.Close(context.Background())
		return nil, err
	}

	net, err := network.New(ctx)
	if err != nil {
		return rollback(fmt.Errorf("create docker network: %w", err))
	}
	p.teardown = append(p.teardown, net.Remove)

	dbReq := testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          mariadbImage,
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {"db"}},
			Env: map[string]string{
				"MYSQL_ROOT_PASSWORD": "passbolt",
				"MYSQL_DATABASE":      "passbolt",
				"MYSQL_USER":          "passbolt",
				"MYSQL_PASSWORD":      "passbolt",
			},
			// MariaDB logs "ready for connections" twice: once during
			// init, again after the post-init restart. Wait for the
			// second occurrence so subsequent connections aren't racing
			// the restart.
			WaitingFor: wait.ForLog("ready for connections").
				WithOccurrence(2).
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	}
	db, err := testcontainers.GenericContainer(ctx, dbReq)
	if err != nil {
		return rollback(fmt.Errorf("start mariadb: %w", err))
	}
	p.teardown = append(p.teardown, func(ctx context.Context) error { return db.Terminate(ctx) })

	pbReq := testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        passboltImage,
			Networks:     []string{net.Name},
			ExposedPorts: []string{"80/tcp"},
			Env: map[string]string{
				"DATASOURCES_DEFAULT_HOST":     "db",
				"DATASOURCES_DEFAULT_USERNAME": "passbolt",
				"DATASOURCES_DEFAULT_PASSWORD": "passbolt",
				"DATASOURCES_DEFAULT_DATABASE": "passbolt",
				// Port-agnostic base URL: register_user prints links
				// with this hostname but we hit the API via the mapped
				// host port. Passbolt CE does not enforce a Host-header
				// match by default.
				"APP_FULL_BASE_URL":  "http://localhost",
				"PASSBOLT_SSL_FORCE": "false",
			},
			WaitingFor: wait.ForHTTP("/healthcheck/status.json").
				WithPort("80/tcp").
				WithStartupTimeout(3 * time.Minute),
		},
		Started: true,
	}
	pb, err := testcontainers.GenericContainer(ctx, pbReq)
	if err != nil {
		return rollback(fmt.Errorf("start passbolt: %w", err))
	}
	p.teardown = append(p.teardown, func(ctx context.Context) error { return pb.Terminate(ctx) })
	p.container = pb

	host, err := pb.Host(ctx)
	if err != nil {
		return rollback(fmt.Errorf("get passbolt host: %w", err))
	}
	port, err := pb.MappedPort(ctx, "80/tcp")
	if err != nil {
		return rollback(fmt.Errorf("get passbolt mapped port: %w", err))
	}
	p.BaseURL = fmt.Sprintf("http://%s:%s", host, port.Port())

	return p, nil
}

// StartT is the *testing.T-bound convenience: starts the stack, registers
// teardown via t.Cleanup, and fatals on error.
func StartT(t *testing.T) *Passbolt {
	t.Helper()
	pb, err := Start(t.Context())
	if err != nil {
		t.Fatalf("testenv start: %v", err)
	}
	t.Cleanup(func() { _ = pb.Close(context.Background()) })
	return pb
}

// setupURLRegex matches the one-time setup link printed by `cake passbolt
// register_user`. Passbolt emits this under /setup/start/<userID>/<token> in
// current versions and historically used /setup/install/...; both forms
// carry the same userID/token pair that the SetupInstall API accepts.
var setupURLRegex = regexp.MustCompile(`https?://\S+/setup/[A-Za-z]+/[A-Za-z0-9-]+/[A-Za-z0-9-]+`)

// RegisterUser invites a user via `cake passbolt register_user` and returns
// the userID and one-time setup token parsed from the printed URL. role must
// be "user" or "admin".
func (p *Passbolt) RegisterUser(ctx context.Context, email, first, last, role string) (userID, token string, err error) {
	// register_user must run as the www-data user so the file Passbolt
	// writes (its registration audit log) has the right ownership.
	cmd := []string{
		"su", "-m", "-c",
		fmt.Sprintf("bin/cake passbolt register_user -u %s -f %s -l %s -r %s",
			email, first, last, role),
		"-s", "/bin/sh", "www-data",
	}
	rc, reader, err := p.container.Exec(ctx, cmd)
	if err != nil {
		return "", "", fmt.Errorf("exec register_user: %w", err)
	}
	out, _ := io.ReadAll(reader)
	if rc != 0 {
		return "", "", fmt.Errorf("register_user exit=%d output:\n%s", rc, out)
	}
	match := setupURLRegex.Find(out)
	if match == nil {
		return "", "", fmt.Errorf("could not find setup URL in register_user output:\n%s", out)
	}
	uid, tok, err := parseInviteURL(string(match))
	if err != nil {
		return "", "", fmt.Errorf("parse invite URL %q: %w", match, err)
	}
	return uid, tok, nil
}

// parseInviteURL splits "<scheme>://<host>/setup/install/<userID>/<token>"
// (with an optional ".json" suffix) into its two trailing components. Mirrors
// helper.ParseInviteURL but lives here so testenv can avoid importing helper,
// which itself imports testenv via the integration test main.
func parseInviteURL(url string) (userID, token string, err error) {
	parts := strings.Split(url, "/")
	if len(parts) < 4 {
		return "", "", fmt.Errorf("invite URL does not have enough slashes: %q", url)
	}
	return parts[len(parts)-2], strings.TrimSuffix(parts[len(parts)-1], ".json"), nil
}

// EnableV5Resources flips the server-side metadata-type and metadata-key
// settings so V5 resources can be created. A fresh Passbolt defaults to
// v4-only (see getV4DefaultMetadataTypeSettings in the api package); without
// this call, every CreateResource for a v5-* type rejects with
// "creation of V5 passwords is disabled on this server".
//
// admin must be a user with the "admin" role; the call opens a short-lived
// admin session and discards it, so caller-side clients still need to be
// (re-)logged-in after this returns to see the new settings in their cache.
func (p *Passbolt) EnableV5Resources(ctx context.Context, admin Credentials) error {
	c, err := api.NewClient(nil, "go-passbolt-testenv-bootstrap", p.BaseURL, admin.PrivateKey, admin.Password)
	if err != nil {
		return fmt.Errorf("admin bootstrap client: %w", err)
	}
	if err := c.Login(ctx); err != nil {
		return fmt.Errorf("admin login: %w", err)
	}
	defer func() { _ = c.Logout(ctx) }()

	// Passbolt refuses to save type settings while no active shared metadata
	// key exists ("An active metadata key could not be found, create a key
	// first"). Bootstrapping one here is the entire reason this method must
	// run before any test client logs in.
	if err := p.createSharedMetadataKey(ctx, c); err != nil {
		return fmt.Errorf("create shared metadata key: %w", err)
	}

	types := api.MetadataTypeSettings{
		DefaultResourceType:        api.PassboltAPIVersionTypeV5,
		DefaultFolderType:          api.PassboltAPIVersionTypeV5,
		DefaultTagType:             api.PassboltAPIVersionTypeV5,
		DefaultCommentType:         api.PassboltAPIVersionTypeV5,
		AllowCreationOfV5Resources: true,
		AllowCreationOfV5Folders:   true,
		AllowCreationOfV5Tags:      true,
		AllowCreationOfV5Comments:  true,
		AllowCreationOfV4Resources: true,
		AllowCreationOfV4Folders:   true,
		AllowCreationOfV4Tags:      true,
		AllowCreationOfV4Comments:  true,
		AllowV4V5Upgrade:           true,
		AllowV4V5Downgrade:         true,
	}
	if _, err := c.DoCustomRequestV5(ctx, "POST", "/metadata/types/settings.json", types, nil); err != nil {
		return fmt.Errorf("post metadata type settings: %w", err)
	}

	// Personal-key mode means each user can act as their own metadata key
	// authority — no shared metadata key bootstrap needed for the test.
	keys := api.MetadataKeySettings{
		AllowUsageOfPersonalKeys:   true,
		AllowZeroKnowledgeKeyShare: false,
	}
	if _, err := c.DoCustomRequestV5(ctx, "POST", "/metadata/keys/settings.json", keys, nil); err != nil {
		return fmt.Errorf("post metadata key settings: %w", err)
	}
	return nil
}

// CreateUser invites the user and completes account setup, returning
// ready-to-use credentials. The returned PrivateKey is ASCII-armored and
// locked with the supplied password.
func (p *Passbolt) CreateUser(ctx context.Context, email, first, last, role, password string) (Credentials, error) {
	userID, token, err := p.RegisterUser(ctx, email, first, last, role)
	if err != nil {
		return Credentials{}, err
	}

	c, err := api.NewClient(nil, "go-passbolt-testenv", p.BaseURL, "", "")
	if err != nil {
		return Credentials{}, fmt.Errorf("registration client: %w", err)
	}
	privKey, err := completeSetup(ctx, c, userID, token, password)
	if err != nil {
		return Credentials{}, fmt.Errorf("setup account for %s: %w", email, err)
	}
	return Credentials{
		UserID:     userID,
		Email:      email,
		Password:   password,
		PrivateKey: privKey,
	}, nil
}

// createSharedMetadataKey generates a fresh PGP keypair for the server's
// shared metadata-key role, encrypts the private half for the supplied admin
// (signed by the admin so the SDK's first-fetch trust path auto-accepts it),
// and POSTs it to /metadata/keys.json. Required before /metadata/types/settings
// will accept any V5-enabling change.
func (p *Passbolt) createSharedMetadataKey(ctx context.Context, admin *api.Client) error {
	me, err := admin.GetMe(ctx)
	if err != nil {
		return fmt.Errorf("get admin user: %w", err)
	}
	if me.GPGKey == nil {
		return fmt.Errorf("admin user has no GPG key in profile")
	}

	pgp := admin.GetPGPHandle()
	key, err := pgp.KeyGeneration().
		AddUserId("Passbolt Shared Metadata Key", "metadata@"+stripScheme(p.BaseURL)).
		New().
		GenerateKey()
	if err != nil {
		return fmt.Errorf("generate metadata keypair: %w", err)
	}
	defer key.ClearPrivateParams()

	publicArmored, err := key.GetArmoredPublicKey()
	if err != nil {
		return fmt.Errorf("armor metadata public key: %w", err)
	}
	privateArmored, err := key.Armor()
	if err != nil {
		return fmt.Errorf("armor metadata private key: %w", err)
	}
	// gopenpgp returns lowercase hex; Passbolt's IsValidFingerprintValidationRule
	// requires uppercase. Mismatch produces a generic 400 "Could not validate
	// the metadata key data".
	fingerprint := strings.ToUpper(key.GetFingerprint())

	// "passphrase must be Empty for Server Keys" per the SDK's
	// MetadataPrivateKeyData comments.
	payload, err := json.Marshal(api.MetadataPrivateKeyData{
		ObjectType:  "PASSBOLT_METADATA_PRIVATE_KEY",
		Domain:      p.BaseURL,
		Fingerprint: fingerprint,
		ArmoredKey:  privateArmored,
		Passphrase:  "",
	})
	if err != nil {
		return fmt.Errorf("marshal metadata private key data: %w", err)
	}

	adminPubKey, err := crypto.NewKeyFromArmored(me.GPGKey.ArmoredKey)
	if err != nil {
		return fmt.Errorf("parse admin public key: %w", err)
	}
	encrypted, err := admin.EncryptMessageWithKey(adminPubKey, string(payload))
	if err != nil {
		return fmt.Errorf("encrypt metadata private key data: %w", err)
	}

	adminID := me.ID
	body := api.MetadataKey{
		Fingerprint: fingerprint,
		ArmoredKey:  publicArmored,
		MetadataPrivateKeys: []api.MetadataPrivateKey{{
			UserID: &adminID,
			Data:   encrypted,
		}},
	}
	if _, err := admin.DoCustomRequestV5(ctx, "POST", "/metadata/keys.json", body, nil); err != nil {
		return fmt.Errorf("post metadata key: %w", err)
	}
	return nil
}

// stripScheme returns the host portion of a URL ("http://localhost:1234" →
// "localhost:1234"). Used to build a plausible email-shaped identity for the
// metadata key's PGP user-id, which Passbolt validates loosely.
func stripScheme(url string) string {
	for _, sep := range []string{"://"} {
		if i := strings.Index(url, sep); i >= 0 {
			return url[i+len(sep):]
		}
	}
	return url
}

// completeSetup runs the GPG-based "setup/complete" flow that turns a
// registration token into a usable, password-locked private key. Mirrors
// helper.SetupAccount; kept here so testenv can stay free of an import on
// helper (which itself depends on testenv from its integration test main).
func completeSetup(ctx context.Context, c *api.Client, userID, token, password string) (string, error) {
	install, err := c.SetupInstall(ctx, userID, token)
	if err != nil {
		return "", fmt.Errorf("setup install: %w", err)
	}

	keyName := install.Profile.FirstName + " " + install.Profile.LastName + " " + install.Username
	pgp := c.GetPGPHandle()

	key, err := pgp.KeyGeneration().AddUserId(keyName, install.Username).New().GenerateKey()
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	defer key.ClearPrivateParams()

	publicKey, err := key.GetArmoredPublicKey()
	if err != nil {
		return "", fmt.Errorf("armor public key: %w", err)
	}

	lockedKey, err := pgp.LockKey(key, []byte(password))
	if err != nil {
		return "", fmt.Errorf("lock private key: %w", err)
	}
	defer lockedKey.ClearPrivateParams()

	privateKey, err := lockedKey.Armor()
	if err != nil {
		return "", fmt.Errorf("armor private key: %w", err)
	}

	req := api.SetupCompleteRequest{
		AuthenticationToken: api.AuthenticationToken{Token: token},
		User:                api.User{Locale: api.UserLocaleENUK},
		GPGKey:              api.GPGKey{ArmoredKey: publicKey},
	}
	if err := c.SetupComplete(ctx, userID, req); err != nil {
		return "", fmt.Errorf("setup complete: %w", err)
	}
	return privateKey, nil
}
