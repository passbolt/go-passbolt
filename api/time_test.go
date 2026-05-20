package api

import (
	"encoding/json"
	"testing"
	"time"
)

// The api.Time wrapper is needed because Passbolt's JSON uses RFC3339
// strings with optional null values, and stdlib time.Time would
// either reject null or accept whatever shape comes through. The
// tests below pin the three behaviors callers depend on.

// TestTime_UnmarshalJSON_RFC3339 is the happy path. We compare with
// time.Time.Equal to avoid timezone-representation false negatives.
func TestTime_UnmarshalJSON_RFC3339(t *testing.T) {
	t.Parallel()

	var got Time
	if err := json.Unmarshal([]byte(`"2026-05-20T10:30:00Z"`), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	want := time.Date(2026, 5, 20, 10, 30, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got.Time, want)
	}
}

// Passbolt's JSON often contains literal `null` for never-set fields
// (e.g. last_modified on a freshly-created record). The wrapper MUST
// accept null and leave the zero value in place — anything else
// breaks deserialization of every API response.
func TestTime_UnmarshalJSON_Null(t *testing.T) {
	t.Parallel()

	var got Time
	if err := json.Unmarshal([]byte(`null`), &got); err != nil {
		t.Fatalf("Unmarshal null: %v", err)
	}
	if !got.IsZero() {
		t.Errorf("Unmarshal null produced non-zero time %v", got.Time)
	}
}

// Garbage input must surface as an error rather than leaking the
// zero value silently — otherwise time comparisons later in helper/
// would compare against year 0001 unexpectedly.
func TestTime_UnmarshalJSON_Invalid(t *testing.T) {
	t.Parallel()

	var got Time
	if err := json.Unmarshal([]byte(`"not a date"`), &got); err == nil {
		t.Error("expected error for invalid date, got nil")
	}
}

// TestTime_MarshalJSON_RoundTrip locks in the wire format. Marshaling
// to anything other than RFC3339 (e.g. epoch seconds, or a different
// layout) would silently break the server's deserializer.
func TestTime_MarshalJSON_RoundTrip(t *testing.T) {
	t.Parallel()

	original := Time{Time: time.Date(2026, 5, 20, 10, 30, 0, 0, time.UTC)}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(raw) != `"2026-05-20T10:30:00Z"` {
		t.Errorf("marshaled = %q, want RFC3339", string(raw))
	}

	var back Time
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("round-trip Unmarshal: %v", err)
	}
	if !back.Equal(original.Time) {
		t.Errorf("round-trip mismatch: %v vs %v", back.Time, original.Time)
	}
}
