// Shared testing infrastructure for the api/ package.
//
// All hermetic tests in this package follow the same pattern:
//
//  1. Build a per-test mock server with exact-match routes via
//     newTestClient, which returns a Client already pointed at it.
//     Unmatched requests fail the test.
//  2. Use writeAPIResponse / writeAPIError / writeMFAChallenge to emit
//     the Passbolt envelope JSON shape.
//  3. Use readJSONBody to inspect what the Client sent (URL, method,
//     body, query) and assert on it.
//
// For tests that need crypto (encrypt / decrypt round-trips, signature
// verification, metadata keys), use newTestClientWithKey which
// initializes the Client with a single test PGP keypair generated once
// per test binary via sync.Once. The keypair is locked with
// testPGPPassphrase.
//
// All helpers call t.Helper() so failures point at the caller's line,
// not the helper.
package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// Reusable UUIDs for tests that need a valid-format UUID but don't care about its value.
const (
	validUUID = "11111111-1111-1111-1111-111111111111"
	otherUUID = "22222222-2222-2222-2222-222222222222"
)

// route declares a single mock-server route: HTTP method, exact path, and handler.
// Routes are matched using Go 1.22+ method-prefixed patterns in http.ServeMux.
type route struct {
	method  string
	path    string
	handler http.HandlerFunc
}

// newMockServer starts a mock server that dispatches requests by exact method+path
// match, and returns its URL together with an http.Client configured for it.
// Unmatched requests fall through to a t.Errorf so routing mistakes are loud rather
// than silent.
//
// Starting the server and registering its Close happen here rather than at the call
// sites: every caller wanted both, and a returned-but-unstarted server is an easy
// thing to get wrong. Handing back (url, client) instead of the *httptest.Server
// keeps callers from reaching for the parts they should not need.
func newMockServer(t testing.TB, routes ...route) (string, *http.Client) {
	t.Helper()
	mux := http.NewServeMux()
	for _, r := range routes {
		mux.HandleFunc(r.method+" "+r.path, r.handler)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to mock server: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client()
}

// newTestClient builds a Client pointed at a fresh mock server with the given
// routes. The Client has no PGP key, which is sufficient for tests of the
// HTTP transport layer and entity CRUD methods.
//
// For tests that need crypto operations, use newTestClientWithKey.
func newTestClient(t testing.TB, routes ...route) *Client {
	t.Helper()
	srvURL, httpClient := newMockServer(t, routes...)
	client, err := NewClient(httpClient, "", srvURL, "", "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// newTestClientWithKey is like newTestClient but arms the Client with the
// shared test PGP keypair (generated once per test binary).
func newTestClientWithKey(t testing.TB, routes ...route) *Client {
	t.Helper()
	priv, pass := testPGPKey(t)
	srvURL, httpClient := newMockServer(t, routes...)
	client, err := NewClient(httpClient, "", srvURL, priv, pass)
	if err != nil {
		t.Fatalf("NewClient with key: %v", err)
	}
	return client
}

// writeAPIResponse encodes a `status="success"` envelope wrapping body as JSON.
// Use this for happy-path mock responses. body may be any JSON-serialisable type.
func writeAPIResponse(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	env := APIResponse{
		Header: APIHeader{Status: "success", Code: 200},
		Body:   raw,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(env); err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
}

// writeAPIError encodes a `status="error"` envelope, signaling the Client
// should produce an *APIError with the given code and message.
func writeAPIError(t *testing.T, w http.ResponseWriter, code int, message string) {
	t.Helper()
	env := APIResponse{
		Header: APIHeader{Status: "error", Code: code, Message: message},
		Body:   json.RawMessage(`{}`),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(env); err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
}

// writeMFAChallenge encodes an envelope DoCustomRequestV5 recognizes as an
// MFA challenge: status="error", code=403, URL suffix /mfa/verify/error.json.
func writeMFAChallenge(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	env := APIResponse{
		Header: APIHeader{
			Status: "error",
			Code:   403,
			URL:    "/mfa/verify/error.json",
		},
		Body: json.RawMessage(`{}`),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(env); err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
}

// readJSONBody decodes the request body into v so tests can assert on what
// the Client serialized. Empty bodies are a no-op.
func readJSONBody(t *testing.T, r *http.Request, v any) {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(raw) == 0 {
		return
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("unmarshal body %q: %v", raw, err)
	}
}

// bg is a shorthand for context.Background() to keep test calls short.
func bg() context.Context { return context.Background() }

// ---- Test PGP keypair ----------------------------------------------------

var (
	testPGPOnce      sync.Once
	testPGPArmored   string
	testPGPPublicArm string
	testPGPErr       error
)

const testPGPPassphrase = "test-passphrase"

// testPGPKey returns a passphrase-locked armored PGP private key generated
// once per test binary. The same passphrase is used for every test.
func testPGPKey(t testing.TB) (privateArmored, passphrase string) {
	t.Helper()
	testPGPOnce.Do(generateTestPGPKey)
	if testPGPErr != nil {
		t.Fatalf("generate test PGP key: %v", testPGPErr)
	}
	return testPGPArmored, testPGPPassphrase
}

// testPGPPublic returns the armored public key matching testPGPKey.
func testPGPPublic(t testing.TB) string {
	t.Helper()
	testPGPOnce.Do(generateTestPGPKey)
	if testPGPErr != nil {
		t.Fatalf("generate test PGP key: %v", testPGPErr)
	}
	return testPGPPublicArm
}

// generateTestKey generates a fresh, unlocked PGP key pair for use as a
// distinct signer/recipient in tests, e.g. a stand-in for the shared
// metadata key, which must have a different fingerprint from the test
// user's own key (testPGPKey) to meaningfully test dual signing.
func generateTestKey(t testing.TB, name, email string) *crypto.Key {
	t.Helper()
	key, err := crypto.PGP().KeyGeneration().AddUserId(name, email).New().GenerateKey()
	if err != nil {
		t.Fatalf("generate test key %q: %v", email, err)
	}
	return key
}

// sessionKeyForTest returns a deterministic crypto.SessionKey suitable for
// populating caches in tests where the key's actual content doesn't matter.
func sessionKeyForTest() *crypto.SessionKey {
	return crypto.NewSessionKeyFromToken([]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}, "aes256")
}

func generateTestPGPKey() {
	pgp := crypto.PGP()
	key, err := pgp.KeyGeneration().
		AddUserId("Passbolt Test", "test@example.com").
		New().
		GenerateKey()
	if err != nil {
		testPGPErr = err
		return
	}
	pub, err := key.GetArmoredPublicKey()
	if err != nil {
		testPGPErr = err
		return
	}
	locked, err := pgp.LockKey(key, []byte(testPGPPassphrase))
	if err != nil {
		testPGPErr = err
		return
	}
	armored, err := locked.Armor()
	if err != nil {
		testPGPErr = err
		return
	}
	testPGPArmored = armored
	testPGPPublicArm = pub
}
