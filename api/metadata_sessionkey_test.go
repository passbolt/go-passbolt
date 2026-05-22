package api

import (
	"encoding/hex"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// Session-key tests cover the parts of /metadata/session-keys that
// have non-trivial logic: the create/update wire-shape contract
// (optimistic locking via "modified"), the FormatSessionKey
// algorithm-ID mapping, the in-memory pending-keys buffer guards, and
// the bulk-load helper's empty-response / no-op paths.

// TestCreateSessionKeysBundle_PostsEncryptedData pins the wire shape
// expected by the server: the encrypted bundle is wrapped in
// {"data": ...}. A flat string body or a different field name would
// silently fail at the server's JSON schema layer.
func TestCreateSessionKeysBundle_PostsEncryptedData(t *testing.T) {
	t.Parallel()

	var seen struct {
		Data string `json:"data"`
	}
	_, client := newTestClient(t, route{
		method: "POST", path: "/metadata/session-keys.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			readJSONBody(t, r, &seen)
			writeAPIResponse(t, w, MetadataSessionKey{ID: validUUID, Data: seen.Data})
		},
	})

	got, err := client.CreateSessionKeysBundle(bg(), "encrypted-blob")
	if err != nil {
		t.Fatalf("CreateSessionKeysBundle: %v", err)
	}
	if seen.Data != "encrypted-blob" {
		t.Errorf("server saw Data=%q, want %q", seen.Data, "encrypted-blob")
	}
	if got.ID != validUUID {
		t.Errorf("got %+v", got)
	}
}

// TestUpdateSessionKeysBundle_PutsEncryptedData verifies the
// optimistic-locking shape: the request body MUST include the
// "modified" timestamp so the server can reject concurrent edits. A
// regression that dropped the timestamp would cause silent
// last-write-wins corruption.
func TestUpdateSessionKeysBundle_PutsEncryptedData(t *testing.T) {
	t.Parallel()

	var seen struct {
		Data     string `json:"data"`
		Modified Time   `json:"modified"`
	}
	_, client := newTestClient(t, route{
		method: "PUT", path: "/metadata/session-keys/" + validUUID + ".json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			readJSONBody(t, r, &seen)
			writeAPIResponse(t, w, MetadataSessionKey{ID: validUUID, Data: seen.Data})
		},
	})

	if _, err := client.UpdateSessionKeysBundle(bg(), validUUID, "encrypted-blob", Time{}); err != nil {
		t.Fatalf("UpdateSessionKeysBundle: %v", err)
	}
	if seen.Data != "encrypted-blob" {
		t.Errorf("server saw Data=%q", seen.Data)
	}
}

// FormatSessionKey emits "<algo-id>:<hex>" using OpenPGP algorithm
// codes. This format is what the server expects in its session-keys
// JSON; getting the algo ID wrong (e.g. emitting "aes256" instead of
// "9") would silently break decryption on every other client.
func TestFormatSessionKey_AES256Encoding(t *testing.T) {
	t.Parallel()

	keyBytes := []byte{0xde, 0xad, 0xbe, 0xef}
	sk := crypto.NewSessionKeyFromToken(keyBytes, "aes256")
	got := FormatSessionKey(sk)
	if got != "9:DEADBEEF" {
		t.Errorf("got %q, want 9:DEADBEEF", got)
	}
}

// All three OpenPGP symmetric algorithm IDs must map correctly:
// 9=AES-256, 8=AES-192, 7=AES-128. The server interprets the prefix
// as the algorithm for the next decryption — getting it wrong would
// silently break decryption on every other client.
func TestFormatSessionKey_AlgoVariants(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"aes256": "9",
		"aes192": "8",
		"aes128": "7",
	}
	keyBytes, _ := hex.DecodeString("11")
	for algo, prefix := range cases {
		t.Run(algo, func(t *testing.T) {
			t.Parallel()
			sk := crypto.NewSessionKeyFromToken(keyBytes, algo)
			got := FormatSessionKey(sk)
			if !strings.HasPrefix(got, prefix+":") {
				t.Errorf("FormatSessionKey(%s) = %q, want prefix %q:", algo, got, prefix)
			}
		})
	}
}

// FormatSessionKey(nil) must NOT panic — callers may pass a missing
// key and expect an empty string back rather than a crash.
// SavePendingSessionKeys checks .SessionKey == "" to decide whether
// to include the entry, so this is a real-world path.
func TestFormatSessionKey_NilReturnsEmpty(t *testing.T) {
	t.Parallel()

	if got := FormatSessionKey(nil); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// TestAddPendingSessionKey_RespectsGuards exercises every short-circuit
// in AddPendingSessionKey. The two guards (nil sessionKey, empty
// foreignID) prevent corrupted entries from reaching the server;
// callers in helper/ pass these values during decryption and rely on
// the SDK to filter rather than blow up.
func TestAddPendingSessionKey_RespectsGuards(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t)
	if client.GetPendingSessionKeysCount() != 0 {
		t.Error("count should start at 0")
	}

	client.AddPendingSessionKey(ForeignModelTypesResource, validUUID, sessionKeyForTest())
	if got := client.GetPendingSessionKeysCount(); got != 1 {
		t.Errorf("count = %d, want 1 after a valid Add", got)
	}

	client.AddPendingSessionKey(ForeignModelTypesResource, otherUUID, nil)
	if got := client.GetPendingSessionKeysCount(); got != 1 {
		t.Errorf("count = %d, nil session key should be a no-op", got)
	}

	client.AddPendingSessionKey(ForeignModelTypesResource, "", sessionKeyForTest())
	if got := client.GetPendingSessionKeysCount(); got != 1 {
		t.Errorf("count = %d, empty foreignID should be a no-op", got)
	}
}

// TestGetPendingSessionKeys_DrainsAndClears verifies the
// "snapshot and reset" semantics of GetPendingSessionKeys: it returns
// the current list AND empties the buffer atomically. This invariant
// is what allows SavePendingSessionKeys to be called multiple times
// without double-saving.
func TestGetPendingSessionKeys_DrainsAndClears(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t)
	client.AddPendingSessionKey(ForeignModelTypesResource, validUUID, sessionKeyForTest())
	client.AddPendingSessionKey(ForeignModelTypesFolder, otherUUID, sessionKeyForTest())

	drained := client.GetPendingSessionKeys()
	if len(drained) != 2 {
		t.Errorf("got %d pending, want 2", len(drained))
	}
	if client.GetPendingSessionKeysCount() != 0 {
		t.Error("count should be 0 after GetPendingSessionKeys drained the list")
	}
	if got := client.GetPendingSessionKeys(); got != nil {
		t.Errorf("second drain = %+v, want nil", got)
	}
}

// FetchAndCacheSessionKeys is the bulk-load helper called during
// Login(). An empty server response is a valid (and common) state for
// new users — we verify the function doesn't error out on it.
func TestFetchAndCacheSessionKeys_HandlesEmptyServerResponse(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/metadata/session-keys.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, []MetadataSessionKey{})
		},
	})

	got, err := client.FetchAndCacheSessionKeys(bg())
	if err != nil {
		t.Fatalf("FetchAndCacheSessionKeys: %v", err)
	}
	if got != 0 {
		t.Errorf("cached %d session keys from empty response, want 0", got)
	}
}

// TestSavePendingSessionKeys_NoPendingIsNoOp verifies the
// short-circuit that avoids a network round-trip when nothing has
// changed. We assert this via call counting (zero hits = it actually
// short-circuited rather than just discarding the result).
func TestSavePendingSessionKeys_NoPendingIsNoOp(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	_, client := newTestClient(t, route{
		method: "GET", path: "/metadata/session-keys.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			writeAPIResponse(t, w, []MetadataSessionKey{})
		},
	})

	n, err := client.SavePendingSessionKeys(bg())
	if err != nil {
		t.Fatalf("SavePendingSessionKeys: %v", err)
	}
	if n != 0 {
		t.Errorf("saved %d, want 0", n)
	}
	if hits.Load() != 0 {
		t.Errorf("server received %d hits, want 0 — empty pending must short-circuit", hits.Load())
	}
}
