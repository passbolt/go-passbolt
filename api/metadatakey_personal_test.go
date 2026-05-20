package api

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// GetMetadataKey has two entirely different code paths gated by the
// (personal, server-allows-personal) tuple. The personal path is
// simpler — it returns the user's own key, no decryption needed — but
// it has subtle preconditions (user must have a GPG key registered,
// client must have a private key loaded). The shared-key path is
// covered separately via DecryptMetadata round-trip tests.

// TestGetMetadataKey_PersonalReturnsUserKey verifies the happy path: when
// the user asks for the personal key AND the server allows it, we
// return the user's own GPGKey ID + the user's private key — no
// asymmetric decryption needed.
func TestGetMetadataKey_PersonalReturnsUserKey(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t, route{
		method: "GET", path: "/users/me.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, User{
				ID:     validUUID,
				GPGKey: &GPGKey{ID: otherUUID, Fingerprint: "FP"},
			})
		},
	})
	client.metadataKeySettings = MetadataKeySettings{AllowUsageOfPersonalKeys: true}

	id, kind, key, err := client.GetMetadataKey(bg(), true)
	if err != nil {
		t.Fatalf("GetMetadataKey: %v", err)
	}
	if id != otherUUID {
		t.Errorf("id = %q, want %q (the GPGKey ID from /users/me)", id, otherUUID)
	}
	if kind != MetadataKeyTypeUserKey {
		t.Errorf("kind = %q, want user_key", kind)
	}
	if key == nil {
		t.Error("expected non-nil key")
	}
}

// Edge case: server claims the current user has no GPG key. This can
// happen for newly-registered users before they finish setup. The SDK
// must surface a descriptive error rather than returning a nil key
// that would crash on first use.
func TestGetMetadataKey_PersonalFailsWhenUserHasNoGPGKey(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t, route{
		method: "GET", path: "/users/me.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, User{ID: validUUID, GPGKey: nil})
		},
	})
	client.metadataKeySettings = MetadataKeySettings{AllowUsageOfPersonalKeys: true}

	_, _, _, err := client.GetMetadataKey(bg(), true)
	if err == nil {
		t.Fatal("expected error when user has no GPG key")
	}
	if !strings.Contains(err.Error(), "GPG Key nil") {
		t.Errorf("err %q should mention missing GPG key", err.Error())
	}
}

// If the client isn't carrying a private key (e.g. post-Logout, or
// pre-Login), the personal path must surface ErrNoPrivateKey so callers
// can re-authenticate.
func TestGetMetadataKey_PersonalFailsWithoutUserPrivateKey(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t) // no user key
	client.metadataKeySettings = MetadataKeySettings{AllowUsageOfPersonalKeys: true}

	_, _, _, err := client.GetMetadataKey(bg(), true)
	if !errors.Is(err, ErrNoPrivateKey) {
		t.Errorf("err = %v, want wrap of ErrNoPrivateKey", err)
	}
}

// GetMetadataKeyByID error paths. The lookup involves three checks in
// sequence — key exists, has a private key for our user, has exactly
// one — and each has its own error message. We test all three because
// callers (especially helper/metadata.go) branch on the message
// strings to decide whether to retry or surface to the user.

func TestGetMetadataKeyByID_NotFound(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t, route{
		method: "GET", path: "/metadata/keys.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, []MetadataKey{{ID: validUUID, MetadataPrivateKeys: []MetadataPrivateKey{}}})
		},
	})

	_, err := client.GetMetadataKeyByID(bg(), otherUUID)
	if err == nil || !strings.Contains(err.Error(), "metadata key not found") {
		t.Errorf("err = %v, want 'metadata key not found'", err)
	}
}

func TestGetMetadataKeyByID_NoPrivateKeyForUser(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t, route{
		method: "GET", path: "/metadata/keys.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, []MetadataKey{
				{ID: validUUID, MetadataPrivateKeys: []MetadataPrivateKey{}},
			})
		},
	})

	_, err := client.GetMetadataKeyByID(bg(), validUUID)
	if err == nil || !strings.Contains(err.Error(), "no Metadata Private key") {
		t.Errorf("err = %v, want 'no Metadata Private key'", err)
	}
}

// TestGetMetadataKeyByID_MoreThanOnePrivateKey: the server should only
// return one private-key entry per user, but a misconfigured response
// must not be silently accepted — picking one at random would mean
// nondeterministic decryption results.
func TestGetMetadataKeyByID_MoreThanOnePrivateKey(t *testing.T) {
	t.Parallel()

	owner := validUUID
	_, client := newTestClientWithKey(t, route{
		method: "GET", path: "/metadata/keys.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, []MetadataKey{
				{
					ID: validUUID,
					MetadataPrivateKeys: []MetadataPrivateKey{
						{ID: "a", UserID: &owner, Data: "x"},
						{ID: "b", UserID: &owner, Data: "y"},
					},
				},
			})
		},
	})

	_, err := client.GetMetadataKeyByID(bg(), validUUID)
	if err == nil || !strings.Contains(err.Error(), "more than 1") {
		t.Errorf("err = %v, want 'more than 1'", err)
	}
}

// TestGetMetadataKeyByID_PrivateKeyForDifferentUser: defense in depth.
// Even if the server mistakenly returns another user's metadata
// private key entry, the SDK must reject it rather than attempt
// decryption — which would either fail cryptographically or
// (worst-case) leak metadata if the server-side ACL is broken.
func TestGetMetadataKeyByID_PrivateKeyForDifferentUser(t *testing.T) {
	t.Parallel()

	other := otherUUID
	_, client := newTestClientWithKey(t, route{
		method: "GET", path: "/metadata/keys.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, []MetadataKey{
				{
					ID: validUUID,
					MetadataPrivateKeys: []MetadataPrivateKey{
						{ID: "a", UserID: &other, Data: "x"},
					},
				},
			})
		},
	})
	client.userID = validUUID // logged-in user differs from privMetdata.UserID

	_, err := client.GetMetadataKeyByID(bg(), validUUID)
	if err == nil || !strings.Contains(err.Error(), "not for our user") {
		t.Errorf("err = %v, want 'not for our user'", err)
	}
}
