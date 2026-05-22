package api

import (
	"net/http"
	"strings"
	"testing"
)

// TestVerifyServer_AcceptsMatchingResponseHeader is the happy path: when
// the server echoes the same plaintext token back via the
// X-GPGAuth-Verify-Response header, VerifyServer accepts it. This proves
// the client's pinning check uses the response header (not, say, the body
// or some other field), which is the entire point of GPGAuth verification.
func TestVerifyServer_AcceptsMatchingResponseHeader(t *testing.T) {
	t.Parallel()

	const token = "gpgauthv1.3.0|36|11111111-2222-3333-4444-555555555555|gpgauthv1.3.0"
	_, client := newTestClientWithKey(t, route{
		method: "POST", path: "/auth/verify.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-GPGAuth-Verify-Response", token)
			writeAPIResponse(t, w, map[string]string{})
		},
	})
	// The encToken value is irrelevant to this test — the production code
	// sends it as part of the JSON request body, but verification depends
	// solely on the server's response header. A real server would decrypt
	// encToken and echo the plaintext back; here we shortcut by echoing
	// token directly.
	if err := client.VerifyServer(bg(), token, "irrelevant-ciphertext"); err != nil {
		t.Fatalf("VerifyServer: %v", err)
	}
}

// TestVerifyServer_RejectsMismatchedResponseHeader is the security-relevant
// path: if the server fails to prove possession of the matching key (by
// returning a different token), VerifyServer must refuse to trust it. A
// regression here would let an attacker-controlled server impersonate the
// legitimate Passbolt instance.
func TestVerifyServer_RejectsMismatchedResponseHeader(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t, route{
		method: "POST", path: "/auth/verify.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-GPGAuth-Verify-Response", "different-token")
			writeAPIResponse(t, w, map[string]string{})
		},
	})
	err := client.VerifyServer(bg(), "expected-token", "enc")
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "Saved Token") {
		t.Errorf("err %q should mention Saved Token mismatch", err.Error())
	}
}

// TestSetupServerVerification_FullRoundTrip exercises the end-to-end
// SetupServerVerification flow:
//
//  1. GET /auth/verify.json — fetch the server's public key
//  2. Client encrypts a freshly generated challenge token with that key
//  3. POST /auth/verify.json — send the encrypted challenge
//  4. Client checks X-GPGAuth-Verify-Response matches the plaintext token
//
// The mock POST handler decrypts the challenge using the SAME key it
// served as "the server's public key" (here, the test PGP keypair plays
// both roles). It then echoes the plaintext back via the response header,
// exactly as a real Passbolt server would. A regression in encryption,
// request-body shape, or response-header parsing makes this test fail.
func TestSetupServerVerification_FullRoundTrip(t *testing.T) {
	t.Parallel()

	pubKey := testPGPPublic(t)

	// Build a stand-in "server" with the same private key the test client
	// uses, so it can decrypt what the client encrypts to its public key.
	serverPrivArmored, serverPass := testPGPKey(t)
	serverPriv, err := GetPrivateKeyFromArmor(serverPrivArmored, []byte(serverPass))
	if err != nil {
		t.Fatalf("setup: load server priv key: %v", err)
	}
	// A throwaway Client that we use only as a decrypt-helper for the mock
	// server handler.
	decryptor, err := NewClient(nil, "", "http://localhost", serverPrivArmored, serverPass)
	if err != nil {
		t.Fatalf("setup: build decryptor: %v", err)
	}

	_, client := newTestClientWithKey(t,
		route{
			method: "GET", path: "/auth/verify.json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeAPIResponse(t, w, PublicKeyReponse{Keydata: pubKey})
			},
		},
		route{
			method: "POST", path: "/auth/verify.json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				// The client posts {"gpg_auth": {"keyid": "...",
				// "server_verify_token": "<armored ciphertext>"}}.
				var body GPGVerifyContainer
				readJSONBody(t, r, &body)

				plaintext, derr := decryptor.DecryptMessage(body.Req.Token)
				if derr != nil {
					t.Errorf("mock server failed to decrypt challenge: %v", derr)
					http.Error(w, "decrypt failed", http.StatusInternalServerError)
					return
				}
				// Echo the decrypted plaintext token back, simulating a
				// healthy Passbolt server proving it holds the private key.
				w.Header().Set("X-GPGAuth-Verify-Response", plaintext)
				writeAPIResponse(t, w, map[string]string{})
			},
		},
	)

	token, encToken, err := client.SetupServerVerification(bg())
	if err != nil {
		t.Fatalf("SetupServerVerification: %v", err)
	}
	if token == "" || encToken == "" {
		t.Errorf("token/encToken should both be non-empty, got %q / %q", token, encToken)
	}
	if !strings.HasPrefix(token, "gpgauthv1.3.0|") {
		t.Errorf("token = %q, want gpgauthv1.3.0 prefix", token)
	}
	// Sanity: the encToken must look like an armored PGP message so that a
	// real server can actually decrypt it.
	if !strings.Contains(encToken, "BEGIN PGP MESSAGE") {
		t.Errorf("encToken does not look armored: %q", encToken)
	}

	// serverPriv is referenced indirectly via decryptor; explicit use keeps
	// the helper compile if the decryptor wiring is ever changed.
	_ = serverPriv
}
