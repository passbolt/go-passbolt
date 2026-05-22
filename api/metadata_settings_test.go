package api

import "testing"

// MetadataTypeSettings and MetadataKeySettings expose their cached
// server-fetched values through getters. The non-trivial invariant
// these getters MUST maintain is "return by value, not by reference"
// — a regression that returned a pointer (or the field's address)
// would let callers mutate the cached settings, silently changing
// behavior for the rest of the session.

// TestMetadataTypeSettings_GetterReturnsByValueCopy mutates the cached
// field after reading, then asserts the returned value did NOT
// change. If the getter aliased the cache, the mutation would be
// visible in `got` and the test would fail.
func TestMetadataTypeSettings_GetterReturnsByValueCopy(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t)
	client.metadataTypeSettings = MetadataTypeSettings{DefaultResourceType: PassboltAPIVersionTypeV5}
	got := client.MetadataTypeSettings()

	client.metadataTypeSettings.DefaultResourceType = PassboltAPIVersionTypeV4
	if got.DefaultResourceType != PassboltAPIVersionTypeV5 {
		t.Errorf("getter aliased the cached field; got.DefaultResourceType changed to %q", got.DefaultResourceType)
	}
}

// Same invariant for MetadataKeySettings.
func TestMetadataKeySettings_GetterReturnsByValueCopy(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t)
	client.metadataKeySettings = MetadataKeySettings{AllowUsageOfPersonalKeys: true}
	got := client.MetadataKeySettings()

	client.metadataKeySettings.AllowUsageOfPersonalKeys = false
	if !got.AllowUsageOfPersonalKeys {
		t.Error("getter aliased the cached field; got.AllowUsageOfPersonalKeys changed")
	}
}
