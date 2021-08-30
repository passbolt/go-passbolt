package api

import (
	"strings"
	"time"
)

// Time is here to unmarshall time correctly
type Time struct {
	time.Time
}

// UnmarshalJSON Parses Passbolt *Time
func (t *Time) UnmarshalJSON(buf []byte) error {
	if string(buf) == "null" {
		return nil
	}
	tt, err := time.Parse(time.RFC3339, strings.Trim(string(buf), `"`))
	if err != nil {
		return err
	}
	t.Time = tt
	return nil
}

// MarshalJSON Marshals Passbolt *Time
func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.Time.Format(time.RFC3339) + `"`), nil
}
