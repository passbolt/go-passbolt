package api

import (
	"testing"
	"time"
)

// FuzzTimeUnmarshalJSON feeds arbitrary bytes to the custom Passbolt time
// unmarshaller (it strips surrounding quotes then time.Parse's the rest).
// Invariant: it never panics, and whenever it accepts the input, marshaling
// the resulting Time back out produces a value that round-trips cleanly through
// RFC3339 — i.e. accepted times are always representable.
func FuzzTimeUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`"2021-01-01T00:00:00Z"`))
	f.Add([]byte(`"2021-01-01T00:00:00.123456789+02:00"`))
	f.Add([]byte("null"))
	f.Add([]byte(`""`))
	f.Add([]byte(`"not a date"`))
	f.Add([]byte(`"2021-13-99T99:99:99Z"`))

	f.Fuzz(func(t *testing.T, buf []byte) {
		var pt Time
		if err := pt.UnmarshalJSON(buf); err != nil {
			return
		}
		// Accepted: marshaling out and parsing back must succeed.
		out, err := pt.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON failed for accepted input %q: %v", buf, err)
		}
		s := string(out)
		if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
			t.Fatalf("MarshalJSON produced non-quoted output %q for input %q", s, buf)
		}
		if _, err := time.Parse(time.RFC3339, s[1:len(s)-1]); err != nil {
			t.Fatalf("round-trip failed: %q -> %q does not parse as RFC3339: %v", buf, s, err)
		}
	})
}
