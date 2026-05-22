package api

import (
	"strings"
	"testing"
)

// Metadata tests focus on the session-key caching layer. V5 resources
// encrypt their metadata (name, username, URI) with shared metadata
// keys, and decrypting them with full asymmetric crypto every time
// would be prohibitively slow. The Client caches the symmetric session
// key extracted on first decrypt and reuses it. We verify the cache is
// actually consulted, not just populated.

// TestEncryptDecryptMetadata_RoundTrip is the basic happy path. Reusing
// the user's own PGP key as the "metadata key" keeps the test
// self-contained; in production these would be distinct keys.
func TestEncryptDecryptMetadata_RoundTrip(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t)
	metaKey, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("GetUserPrivateKeyCopy: %v", err)
	}

	want := `{"name":"Stripe","username":"alice@example.com"}`
	armored, err := client.EncryptMetadata(metaKey, want)
	if err != nil {
		t.Fatalf("EncryptMetadata: %v", err)
	}
	if !strings.Contains(armored, "BEGIN PGP MESSAGE") {
		t.Errorf("encrypted output not armored: %q", armored)
	}

	got, err := client.DecryptMetadata(metaKey, armored)
	if err != nil {
		t.Fatalf("DecryptMetadata: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch: got %q, want %q", got, want)
	}
}

// TestDecryptMetadataWithKeyID_CachesSessionKey is the load-bearing
// caching test. The trick: on the second decrypt we pass nil for the
// metaKey. If the cache wasn't consulted, decryptMessageWithPrivateKeyDirect
// would crash on nil; the only way this test passes is if the session
// key extracted on the first call was used to short-circuit the second.
// This catches any regression that breaks the cache lookup OR the cache
// write.
func TestDecryptMetadataWithKeyID_CachesSessionKey(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t)
	metaKey, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("GetUserPrivateKeyCopy: %v", err)
	}

	want := "metadata-payload"
	armored, err := client.EncryptMetadata(metaKey, want)
	if err != nil {
		t.Fatalf("EncryptMetadata: %v", err)
	}

	const keyID = "metadata-key-id-1"

	if before := client.GetSessionKeyByMetadataKeyID(keyID); before != nil {
		t.Fatalf("session key cache pre-populated: %+v", before)
	}

	// First call: should populate the cache as a side effect.
	got, err := client.DecryptMetadataWithKeyID(keyID, metaKey, armored)
	if err != nil {
		t.Fatalf("first DecryptMetadataWithKeyID: %v", err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if after := client.GetSessionKeyByMetadataKeyID(keyID); after == nil {
		t.Fatal("session key was not cached after first decrypt")
	}

	// Second call with nil metaKey: only succeeds if the cache hit
	// path is actually used. A nil-deref here would mean the cache was
	// ignored.
	got2, err := client.DecryptMetadataWithKeyID(keyID, nil, armored)
	if err != nil {
		t.Fatalf("second DecryptMetadataWithKeyID (cache path): %v", err)
	}
	if got2 != want {
		t.Errorf("cached decrypt got %q, want %q", got2, want)
	}
}

// TestDecryptMetadataWithKeyID_EmptyKeyIDSkipsCache verifies the cache is
// gated on a non-empty key ID — caching against an empty key would mean
// two distinct metadata keys could collide and serve each other's
// session key, breaking decryption silently.
func TestDecryptMetadataWithKeyID_EmptyKeyIDSkipsCache(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t)
	metaKey, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("GetUserPrivateKeyCopy: %v", err)
	}
	armored, err := client.EncryptMetadata(metaKey, "x")
	if err != nil {
		t.Fatalf("EncryptMetadata: %v", err)
	}

	got, err := client.DecryptMetadataWithKeyID("", metaKey, armored)
	if err != nil {
		t.Fatalf("DecryptMetadataWithKeyID: %v", err)
	}
	if got != "x" {
		t.Errorf("got %q, want x", got)
	}
	if sk := client.GetSessionKeyByMetadataKeyID(""); sk != nil {
		t.Errorf("session key cached under empty ID: %+v", sk)
	}
}

// TestDecryptMetadataWithResourceID_UsesResourceCacheFirst proves the
// resource-aware fast path actually fires. After the first decrypt
// populates the resource-keyed cache, a second decrypt with nil metaKey
// must still succeed via that cache — proving the lookup happens and
// nothing falls through to asymmetric crypto.
func TestDecryptMetadataWithResourceID_UsesResourceCacheFirst(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t)
	metaKey, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("GetUserPrivateKeyCopy: %v", err)
	}

	want := "resource-metadata"
	armored, err := client.EncryptMetadata(metaKey, want)
	if err != nil {
		t.Fatalf("EncryptMetadata: %v", err)
	}

	const resourceID = "11111111-1111-1111-1111-111111111111"
	const keyID = "key-1"

	got, err := client.DecryptMetadataWithResourceID(resourceID, keyID, metaKey, armored)
	if err != nil {
		t.Fatalf("first DecryptMetadataWithResourceID: %v", err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if sk := client.GetSessionKeyByResourceID(resourceID); sk == nil {
		t.Fatal("resource session key was not cached after first decrypt")
	}

	got2, err := client.DecryptMetadataWithResourceID(resourceID, "", nil, armored)
	if err != nil {
		t.Fatalf("second DecryptMetadataWithResourceID (cache path): %v", err)
	}
	if got2 != want {
		t.Errorf("got %q, want %q", got2, want)
	}
}

// TestEncryptMetadata_FailsWithoutClientKey confirms the encryption path
// needs the *client's* private key (for signing) — not just the metadata
// recipient key. A regression that omitted the signing key would
// silently produce unsigned metadata, which the server would reject.
func TestEncryptMetadata_FailsWithoutClientKey(t *testing.T) {
	t.Parallel()

	_, keyed := newTestClientWithKey(t)
	metaKey, err := keyed.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, unkeyed := newTestClient(t) // no user key on this client
	_, err = unkeyed.EncryptMetadata(metaKey, "x")
	if err == nil {
		t.Fatal("expected error encrypting without user key, got nil")
	}
}
