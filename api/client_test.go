package api

import (
	"net/http"
	"strings"
	"testing"
)

// Client construction tests focus on the parts of NewClient that have
// real failure modes: caller-aliasing the http.Client (would mutate
// http.DefaultClient process-wide), accepting malformed URLs or PGP
// keys (would crash later), and the GetPublicKey security invariant
// (must NOT trust the server-provided fingerprint).

// TestNewClient_DoesNotMutateCallerHTTPClient guards the documented
// shallow-copy behavior: callers may pass http.DefaultClient without
// us installing a CheckRedirect on the global default (which would
// affect every other consumer in the process). This is the kind of
// subtle production bug that's almost impossible to debug after the
// fact.
func TestNewClient_DoesNotMutateCallerHTTPClient(t *testing.T) {
	t.Parallel()

	caller := &http.Client{}
	client, err := NewClient(caller, "my-agent/2", "http://example.test", "", "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.userAgent != "my-agent/2" {
		t.Errorf("userAgent = %q, want %q", client.userAgent, "my-agent/2")
	}
	if client.httpClient == caller {
		t.Error("Client wraps the caller's http.Client by reference; a shallow copy is required")
	}
	if caller.CheckRedirect != nil {
		t.Error("Caller's http.Client.CheckRedirect was mutated; NewClient must only modify its own copy")
	}
	if client.httpClient.CheckRedirect == nil {
		t.Error("Client's http.Client must have CheckRedirect installed for cross-host protection")
	}
}

// TestNewClient_BadURL ensures malformed base URLs are rejected at
// construction rather than blowing up later inside a request.
func TestNewClient_BadURL(t *testing.T) {
	t.Parallel()

	_, err := NewClient(nil, "", "://not-a-url", "", "")
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
	if !strings.Contains(err.Error(), "parsing Base URL") {
		t.Errorf("error %q should mention URL parsing", err.Error())
	}
}

// TestNewClient_InvalidPrivateKey ensures NewClient surfaces PGP
// parsing failures rather than silently constructing a Client with a
// broken key that would crash on first crypto operation.
func TestNewClient_InvalidPrivateKey(t *testing.T) {
	t.Parallel()

	_, err := NewClient(nil, "", "http://example.test", "not a real PGP key", "")
	if err == nil {
		t.Fatal("expected error for garbage private key, got nil")
	}
	if !strings.Contains(err.Error(), "Private Key") {
		t.Errorf("error %q should mention Private Key parsing", err.Error())
	}
}

// TestGetPublicKey_ComputesFingerprintLocally is the security-relevant
// invariant: the server returns both a keydata blob AND a self-reported
// fingerprint, and the Client must NEVER trust the latter. If
// GetPublicKey echoed the server's fingerprint, a malicious server
// could trick clients into pinning the wrong fingerprint.
func TestGetPublicKey_ComputesFingerprintLocally(t *testing.T) {
	t.Parallel()

	pubKey := testPGPPublic(t)
	_, client := newTestClient(t, route{
		method: "GET", path: "/auth/verify.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, PublicKeyReponse{
				Fingerprint: "ATTACKER-PROVIDED-FINGERPRINT",
				Keydata:     pubKey,
			})
		},
	})

	keydata, fingerprint, err := client.GetPublicKey(bg())
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if keydata != pubKey {
		t.Errorf("keydata was not returned verbatim")
	}
	if fingerprint == "ATTACKER-PROVIDED-FINGERPRINT" {
		t.Error("GetPublicKey returned the server-provided fingerprint; it must compute it from the key")
	}
	if fingerprint == "" {
		t.Error("computed fingerprint should not be empty")
	}
}

// TestGetPublicKey_RejectsInvalidServerKey makes sure a broken or
// malicious server response surfaces as an error rather than letting
// downstream code operate on a nil/invalid key.
func TestGetPublicKey_RejectsInvalidServerKey(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/auth/verify.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, PublicKeyReponse{Keydata: "not a valid PGP key"})
		},
	})

	_, _, err := client.GetPublicKey(bg())
	if err == nil {
		t.Fatal("expected error for invalid server key, got nil")
	}
	if !strings.Contains(err.Error(), "Server Key") {
		t.Errorf("error %q should mention Server Key", err.Error())
	}
}
