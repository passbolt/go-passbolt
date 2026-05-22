package api

import (
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
)

// Client cache tests verify the in-memory caches the SDK uses to
// avoid repeated network round-trips during a session. All of these
// caches are populated lazily — the tests prove that subsequent
// lookups don't re-hit the server, and that missing entries surface
// as typed errors rather than nils.

// TestGetResourceTypeCached_PopulatesCacheAndServesRepeat counts
// server hits across two lookups (by different IDs). The first call
// populates the cache; the second must serve from memory. A
// regression that always re-fetched would surface as calls=2.
func TestGetResourceTypeCached_PopulatesCacheAndServesRepeat(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	_, client := newTestClient(t, route{
		method: "GET", path: "/resource-types.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			writeAPIResponse(t, w, []ResourceType{
				{ID: validUUID, Slug: "password-and-description"},
				{ID: otherUUID, Slug: "v5-default"},
			})
		},
	})

	got, err := client.GetResourceTypeCached(bg(), otherUUID)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if got.Slug != "v5-default" {
		t.Errorf("got %+v", got)
	}

	got2, err := client.GetResourceTypeCached(bg(), validUUID)
	if err != nil {
		t.Fatalf("second call (cache hit on different ID): %v", err)
	}
	if got2.Slug != "password-and-description" {
		t.Errorf("got %+v", got2)
	}

	if got := calls.Load(); got != 1 {
		t.Errorf("server saw %d calls, want 1 — cache should serve the second lookup", got)
	}
}

// Cache miss for an unknown ID must surface as ErrResourceTypeNotFound
// (typed) rather than a nil pointer, because helper/ code branches on
// the typed error to decide whether to fall back to default schema.
func TestGetResourceTypeCached_NotFoundError(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/resource-types.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, []ResourceType{{ID: validUUID}})
		},
	})
	_, err := client.GetResourceTypeCached(bg(), otherUUID)
	if !errors.Is(err, ErrResourceTypeNotFound) {
		t.Errorf("err = %v, want ErrResourceTypeNotFound", err)
	}
}

// GetResourceTypeBySlugCached takes a slug rather than a UUID. The
// helper/ package calls this when creating v5 resources to discover
// the correct resource_type_id for a given resource shape.
func TestGetResourceTypeBySlugCached_FindsBySlug(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/resource-types.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, []ResourceType{
				{ID: validUUID, Slug: "v5-default"},
				{ID: otherUUID, Slug: "v5-totp-standalone"},
			})
		},
	})

	got, err := client.GetResourceTypeBySlugCached(bg(), "v5-totp-standalone")
	if err != nil {
		t.Fatalf("GetResourceTypeBySlugCached: %v", err)
	}
	if got.ID != otherUUID {
		t.Errorf("got %+v", got)
	}
}

func TestGetResourceTypeBySlugCached_NotFoundError(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/resource-types.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, []ResourceType{{ID: validUUID, Slug: "v5-default"}})
		},
	})
	_, err := client.GetResourceTypeBySlugCached(bg(), "nonexistent")
	if !errors.Is(err, ErrResourceTypeNotFound) {
		t.Errorf("err = %v, want ErrResourceTypeNotFound", err)
	}
}

// TestGetMetadataKeysCached_OnlyHitsServerOnce: same call-counting
// strategy as the resource-types test. The metadata keys cache is
// particularly critical because the keys carry encrypted private
// material — refetching them repeatedly would magnify both network
// load and exposure window.
func TestGetMetadataKeysCached_OnlyHitsServerOnce(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	_, client := newTestClient(t, route{
		method: "GET", path: "/metadata/keys.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			writeAPIResponse(t, w, []MetadataKey{{ID: validUUID}})
		},
	})

	for i := 0; i < 3; i++ {
		got, err := client.GetMetadataKeysCached(bg())
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if len(got) != 1 {
			t.Fatalf("call %d returned %d keys, want 1", i, len(got))
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server saw %d calls, want 1", got)
	}
}

// GetDecryptedMetadataKeyCached returns ErrMetadataKeyNotFound when
// the ID doesn't exist server-side. Callers (e.g. metadata.go) use
// this to decide between "retry with a different key" and "give up".
func TestGetDecryptedMetadataKeyCached_NotFound(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t, route{
		method: "GET", path: "/metadata/keys.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, []MetadataKey{})
		},
	})
	_, err := client.GetDecryptedMetadataKeyCached(bg(), validUUID)
	if !errors.Is(err, ErrMetadataKeyNotFound) {
		t.Errorf("err = %v, want ErrMetadataKeyNotFound", err)
	}
}

// Different error path: the key exists but has no private-key entry
// for our user. This happens when a key has been added but not yet
// shared with us. ErrNoMetadataPrivateKey is the documented sentinel.
func TestGetDecryptedMetadataKeyCached_NoPrivateKeyForUser(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t, route{
		method: "GET", path: "/metadata/keys.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, []MetadataKey{
				{ID: validUUID, MetadataPrivateKeys: nil},
			})
		},
	})
	_, err := client.GetDecryptedMetadataKeyCached(bg(), validUUID)
	if !errors.Is(err, ErrNoMetadataPrivateKey) {
		t.Errorf("err = %v, want ErrNoMetadataPrivateKey", err)
	}
}

// PreFetchCaches is the bulk-warm-up called during Login on v5
// servers. It's wrapped in two log-but-don't-fail try blocks because
// neither cache is strictly required for correctness — Login should
// succeed even if both fail. We assert the empty/empty path returns
// (0, 0, nil).
func TestPreFetchCaches_HappyPathReturnsCounts(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t,
		route{
			method: "GET", path: "/metadata/session-keys.json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeAPIResponse(t, w, []MetadataSessionKey{})
			},
		},
		route{
			method: "GET", path: "/metadata/keys.json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeAPIResponse(t, w, []MetadataKey{})
			},
		},
	)

	sessionCount, metadataCount, err := client.PreFetchCaches(bg())
	if err != nil {
		t.Fatalf("PreFetchCaches: %v", err)
	}
	if sessionCount != 0 || metadataCount != 0 {
		t.Errorf("got session=%d metadata=%d, want 0/0", sessionCount, metadataCount)
	}
}

// Empty keys list is a valid state for a fresh server install or a
// user who hasn't been granted any v5 keys yet.
func TestPreDecryptAllMetadataPrivateKeys_EmptyKeysReturnsZero(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t, route{
		method: "GET", path: "/metadata/keys.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, []MetadataKey{})
		},
	})

	got, err := client.PreDecryptAllMetadataPrivateKeys(bg())
	if err != nil {
		t.Fatalf("PreDecryptAllMetadataPrivateKeys: %v", err)
	}
	if got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

// TestPreDecryptAllMetadataPrivateKeys_SkipsKeysItCannotDecrypt
// covers the continue-on-error invariant: a single broken key (e.g.
// one that's not shared with our user) must NOT abort the whole
// bulk-decrypt. Otherwise one bad key would block Login entirely.
func TestPreDecryptAllMetadataPrivateKeys_SkipsKeysItCannotDecrypt(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t, route{
		method: "GET", path: "/metadata/keys.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, []MetadataKey{
				{ID: validUUID, MetadataPrivateKeys: nil},
				{ID: otherUUID, MetadataPrivateKeys: nil},
			})
		},
	})

	got, err := client.PreDecryptAllMetadataPrivateKeys(bg())
	if err != nil {
		t.Fatalf("PreDecryptAllMetadataPrivateKeys: %v", err)
	}
	if got != 0 {
		t.Errorf("got %d decrypted, want 0 (all should be skipped)", got)
	}
}

// setMetadataTypeSettings is part of Login's "now figure out what
// kind of server we're talking to" step. The branch is gated by
// IsPluginEnabled("metadata"); when enabled, we fetch and store the
// type+key settings, otherwise we use hard-coded v4 defaults. Both
// branches drive whether the SDK creates v4 or v5 resources by
// default, so they're load-bearing.
func TestSetMetadataTypeSettings_FetchesWhenPluginEnabled(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t,
		route{
			method: "GET", path: "/metadata/types/settings.json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeAPIResponse(t, w, MetadataTypeSettings{
					AllowCreationOfV5Resources: true,
					DefaultResourceType:        PassboltAPIVersionTypeV5,
				})
			},
		},
		route{
			method: "GET", path: "/metadata/keys/settings.json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeAPIResponse(t, w, MetadataKeySettings{AllowUsageOfPersonalKeys: true})
			},
		},
	)

	settings := &ServerSettingsResponse{
		Passbolt: ServerPassboltSettings{
			Plugins: map[string]ServerPassboltPluginSettings{
				"metadata": {Enabled: true},
			},
		},
	}
	if err := client.setMetadataTypeSettings(bg(), settings); err != nil {
		t.Fatalf("setMetadataTypeSettings: %v", err)
	}
	if !client.metadataTypeSettings.AllowCreationOfV5Resources {
		t.Errorf("AllowCreationOfV5Resources should have been set from server")
	}
	if !client.metadataKeySettings.AllowUsageOfPersonalKeys {
		t.Errorf("AllowUsageOfPersonalKeys should have been set from server")
	}
}

// Counterpart: when the plugin is absent or disabled, no HTTP call is
// made and the v4 defaults take effect. A regression that
// unconditionally fetched would error out on v4-only servers.
func TestSetMetadataTypeSettings_FallsBackToV4WhenPluginDisabled(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t)
	settings := &ServerSettingsResponse{
		Passbolt: ServerPassboltSettings{
			Plugins: map[string]ServerPassboltPluginSettings{},
		},
	}
	if err := client.setMetadataTypeSettings(bg(), settings); err != nil {
		t.Fatalf("setMetadataTypeSettings: %v", err)
	}
	if client.metadataTypeSettings.DefaultResourceType != PassboltAPIVersionTypeV4 {
		t.Errorf("default = %q, want v4", client.metadataTypeSettings.DefaultResourceType)
	}
}

// setPasswordExpirySettings follows the same enabled/disabled pattern
// as setMetadataTypeSettings. Both flags must be enabled
// (passwordExpiry AND passwordExpiryPolicies) for the SDK to fetch
// from the server — a half-enabled state must fall back to defaults.
func TestSetPasswordExpirySettings_FetchesWhenPluginEnabled(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/password-expiry/settings.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, PasswordExpirySettings{ID: validUUID, DefaultExpiryPeriod: 90})
		},
	})

	settings := &ServerSettingsResponse{
		Passbolt: ServerPassboltSettings{
			Plugins: map[string]ServerPassboltPluginSettings{
				"passwordExpiry":         {Enabled: true},
				"passwordExpiryPolicies": {Enabled: true},
			},
		},
	}
	if err := client.setPasswordExpirySettings(bg(), settings); err != nil {
		t.Fatalf("setPasswordExpirySettings: %v", err)
	}
	if client.passwordExpirySettings.DefaultExpiryPeriod != 90 {
		t.Errorf("DefaultExpiryPeriod = %d, want 90", client.passwordExpirySettings.DefaultExpiryPeriod)
	}
}

func TestSetPasswordExpirySettings_FallsBackToDefaultsWhenPluginDisabled(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t)
	settings := &ServerSettingsResponse{
		Passbolt: ServerPassboltSettings{Plugins: map[string]ServerPassboltPluginSettings{}},
	}
	if err := client.setPasswordExpirySettings(bg(), settings); err != nil {
		t.Fatalf("setPasswordExpirySettings: %v", err)
	}
	if client.passwordExpirySettings.ID != "default" {
		t.Errorf("ID = %q, want default", client.passwordExpirySettings.ID)
	}
}
