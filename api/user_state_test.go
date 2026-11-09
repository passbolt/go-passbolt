package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestUserStateRequests(t *testing.T) {
	for _, disable := range []bool{false, true} {
		name := "enable"
		if disable {
			name = "disable"
		}
		t.Run(name, func(t *testing.T) {
			before := time.Now().UTC().Truncate(time.Second)
			c := newTestClient(t, route{method: "PUT", path: "/users/" + validUUID + ".json", handler: func(w http.ResponseWriter, r *http.Request) {
				var body map[string]json.RawMessage
				readJSONBody(t, r, &body)
				raw, ok := body["disabled"]
				if !ok || len(body) != 1 {
					t.Fatalf("expected only explicit disabled field, got %s", body)
				}
				if !disable {
					if string(raw) != "null" {
						t.Errorf("disabled = %s, want null", raw)
					}
				} else {
					var value string
					if err := json.Unmarshal(raw, &value); err != nil {
						t.Fatal(err)
					}
					stamp, err := time.Parse("2006-01-02 15:04:05", value)
					if err != nil {
						t.Fatalf("expected CakePHP UTC datetime: %v", err)
					}
					if stamp.Before(before) || stamp.After(time.Now().UTC()) {
						t.Errorf("disabled timestamp %s outside request window", stamp)
					}
				}
				writeAPIResponse(t, w, map[string]any{})
			}})
			var err error
			if disable {
				err = c.DisableUser(context.Background(), validUUID)
			} else {
				err = c.EnableUser(context.Background(), validUUID)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUserStateInvalidID(t *testing.T) {
	c := newTestClient(t)
	for _, call := range []func(context.Context, string) error{c.DisableUser, c.EnableUser} {
		if err := call(context.Background(), "invalid"); !errors.Is(err, ErrInvalidUUID) {
			t.Fatalf("error = %v, want invalid UUID", err)
		}
	}
}

func TestUserStatePropagatesAPIError(t *testing.T) {
	c := newTestClient(t, route{method: "PUT", path: "/users/" + validUUID + ".json", handler: func(w http.ResponseWriter, r *http.Request) { writeAPIError(t, w, 403, "forbidden") }})
	for _, call := range []func(context.Context, string) error{c.DisableUser, c.EnableUser} {
		err := call(context.Background(), validUUID)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != 403 {
			t.Errorf("error = %v, want API 403", err)
		}
	}
}
