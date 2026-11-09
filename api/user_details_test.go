package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestUserAdministrativeFieldsPreserveMissingAndFalse(t *testing.T) {
	for _, tc := range []struct {
		body           string
		known, enabled bool
	}{{`{"id":"` + validUUID + `"}`, false, false}, {`{"is_mfa_enabled":false,"scim_entry":{"external_id":"directory-id","counter":9007199254740993}}`, true, false}, {`{"is_mfa_enabled":true}`, true, true}, {`{"is_mfa_enabled":null}`, false, false}} {
		var user User
		if err := json.Unmarshal([]byte(tc.body), &user); err != nil {
			t.Fatal(err)
		}
		if (user.IsMFAEnabled != nil) != tc.known {
			t.Fatalf("MFA presence=%v for %s", user.IsMFAEnabled, tc.body)
		}
		if tc.known && *user.IsMFAEnabled != tc.enabled {
			t.Errorf("MFA=%v", *user.IsMFAEnabled)
		}
		out, err := json.Marshal(user)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(out, &fields); err != nil {
			t.Fatal(err)
		}
		if tc.known && fields["is_mfa_enabled"] == nil {
			t.Errorf("lost explicit false: %s", out)
		}
		if user.ScimEntry != nil {
			var entry map[string]json.RawMessage
			if err := json.Unmarshal(fields["scim_entry"], &entry); err != nil {
				t.Fatal(err)
			}
			if string(entry["counter"]) != "9007199254740993" {
				t.Errorf("changed SCIM data %s", out)
			}
		}
	}
}

func TestGetUserWithAdministrativeOptions(t *testing.T) {
	c := newTestClient(t, route{method: "GET", path: "/users/" + validUUID + ".json", handler: func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("contain[scim_entry]") != "true" {
			t.Errorf("query=%s", r.URL.RawQuery)
		}
		writeAPIResponse(t, w, json.RawMessage(`{"id":"`+validUUID+`","is_mfa_enabled":false,"scim_entry":{"external_id":"directory-id"}}`))
	}})
	user, err := c.GetUserWithOptions(context.Background(), validUUID, &GetUserOptions{ContainSCIMEntry: true})
	if err != nil {
		t.Fatal(err)
	}
	if user.IsMFAEnabled == nil || *user.IsMFAEnabled || user.ScimEntry == nil {
		t.Errorf("user=%+v", user)
	}
}

func TestListUsersMFAFilterAndSCIMOptions(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		c := newTestClient(t, route{method: "GET", path: "/users.json", handler: func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query()
			want := "false"
			if enabled {
				want = "true"
			}
			if query.Get("filter[is-mfa-enabled]") != want || query.Get("contain[is_mfa_enabled]") != "true" || query.Get("contain[scim_entry]") != "true" {
				t.Errorf("query=%s", r.URL.RawQuery)
			}
			writeAPIResponse(t, w, []User{})
		}})
		opts := &GetUsersOptions{FilterIsMFAEnabled: &enabled, ContainSCIMEntry: true}
		if _, err := c.GetUsers(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
		if opts.ContainIsMFAEnabled {
			t.Fatal("mutated caller options")
		}
	}
}
