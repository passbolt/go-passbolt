package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"testing"
)

// These method/path pairs are the organization routes declared by the Passbolt
// CE and EE plugins, rather than generic organization_settings CRUD endpoints.
var organizationSettingsRoutes = []struct {
	name, path                    string
	read, write, delete, deleteID bool
}{
	{"account-recovery-policies", "/account-recovery/organization-policies.json", true, true, false, false},
	{"directory-sync", "/directorysync/settings.json", true, true, true, false},
	{"email-notifications", "/settings/emails/notifications.json", true, true, false, false},
	{"export-policies", "/export-policies/settings.json", true, false, false, false},
	{"locale", "/locale/settings.json", false, true, false, false},
	{"metadata-keys", "/metadata/keys/settings.json", true, true, false, false},
	{"metadata-types", "/metadata/types/settings.json", true, true, false, false},
	{"mfa", "/mfa/settings.json", true, true, false, false},
	{"mfa-policies", "/mfa-policies/settings.json", true, true, false, false},
	{"password-expiry", "/password-expiry/settings.json", true, true, true, true},
	{"password-policies", "/password-policies/settings.json", true, true, false, false},
	{"scim", "/scim/settings.json", true, true, true, true},
	{"secret-revisions", "/secret-revisions/settings.json", true, true, true, false},
	{"self-registration", "/self-registration/settings.json", true, true, true, true},
	{"smtp", "/smtp/settings.json", true, true, false, false},
	{"sso", "/sso/settings.json", true, true, true, true},
	{"user-key-policies", "/user-key-policies/settings.json", true, false, false, false},
	{"user-passphrase-policies", "/user-passphrase-policies/settings.json", true, true, false, false},
}

func TestOrganizationSettingsRequests(t *testing.T) {
	input := json.RawMessage(`{"nested":{"enabled":false,"unset":null},"counter":9007199254740993}`)
	for _, spec := range organizationSettingsRoutes {
		for _, method := range []string{"GET", "POST", "DELETE"} {
			supported := method == "GET" && spec.read || method == "POST" && spec.write || method == "DELETE" && spec.delete
			if !supported {
				continue
			}
			t.Run(spec.name+"/"+method, func(t *testing.T) {
				path, id := spec.path, ""
				if method == "DELETE" && spec.deleteID {
					path = path[:len(path)-len(".json")] + "/" + validUUID + ".json"
					id = validUUID
				}
				c := newTestClient(t, route{method: method, path: path, handler: func(w http.ResponseWriter, r *http.Request) {
					if r.URL.RawQuery != "" {
						t.Errorf("unexpected query %s", r.URL.RawQuery)
					}
					if method == "POST" {
						var body json.RawMessage
						readJSONBody(t, r, &body)
						// Use RawMessage values to avoid rounding the counter in the test itself.
						var gotFields, wantFields map[string]json.RawMessage
						if err := json.Unmarshal(body, &gotFields); err != nil {
							t.Fatal(err)
						}
						if err := json.Unmarshal(input, &wantFields); err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(gotFields, wantFields) {
							t.Errorf("body=%s, want %s", body, input)
						}
					} else if r.ContentLength > 0 {
						t.Error("unexpected request body")
					}
					writeAPIResponse(t, w, json.RawMessage(`{"server_field":false,"counter":9007199254740993,"sources_file":{"x":true}}`))
				}})
				var out json.RawMessage
				var err error
				switch method {
				case "GET":
					out, err = c.GetOrganizationSettings(context.Background(), spec.name)
				case "POST":
					out, err = c.SetOrganizationSettings(context.Background(), spec.name, input)
				case "DELETE":
					err = c.DeleteOrganizationSettings(context.Background(), spec.name, id)
				}
				if err != nil {
					t.Fatal(err)
				}
				if method != "DELETE" {
					var fields map[string]json.RawMessage
					if err := json.Unmarshal(out, &fields); err != nil {
						t.Fatal(err)
					}
					if string(fields["server_field"]) != "false" || string(fields["counter"]) != "9007199254740993" || fields["sources_file"] == nil {
						t.Errorf("response body changed: %s", out)
					}
				}
			})
		}
	}
}

func TestOrganizationSettingsRejectsInvalidRequestsWithoutHTTP(t *testing.T) {
	c := newTestClient(t)
	for _, name := range []string{"", "unknown", "../users", "smtp?x=y"} {
		if _, err := c.GetOrganizationSettings(context.Background(), name); err == nil {
			t.Errorf("accepted get plugin %q", name)
		}
		if _, err := c.SetOrganizationSettings(context.Background(), name, json.RawMessage(`{}`)); err == nil {
			t.Errorf("accepted set plugin %q", name)
		}
		if err := c.DeleteOrganizationSettings(context.Background(), name, ""); err == nil {
			t.Errorf("accepted delete plugin %q", name)
		}
	}
	for _, spec := range organizationSettingsRoutes {
		if !spec.read {
			if _, err := c.GetOrganizationSettings(context.Background(), spec.name); err == nil {
				t.Errorf("accepted unsupported get %s", spec.name)
			}
		}
		if !spec.write {
			if _, err := c.SetOrganizationSettings(context.Background(), spec.name, json.RawMessage(`{}`)); err == nil {
				t.Errorf("accepted unsupported set %s", spec.name)
			}
		}
		if !spec.delete {
			if err := c.DeleteOrganizationSettings(context.Background(), spec.name, ""); err == nil {
				t.Errorf("accepted unsupported delete %s", spec.name)
			}
		}
		if spec.deleteID {
			for _, id := range []string{"", "invalid", "../settings"} {
				if err := c.DeleteOrganizationSettings(context.Background(), spec.name, id); err == nil {
					t.Errorf("accepted delete ID %q for %s", id, spec.name)
				}
			}
		}
	}
	if err := c.DeleteOrganizationSettings(context.Background(), "directory-sync", validUUID); err == nil {
		t.Error("accepted ID for plugin with singleton delete route")
	}
	for _, input := range []string{"", "null", "[]", `"value"`, "true", "42", "{}{}", "{invalid}"} {
		if _, err := c.SetOrganizationSettings(context.Background(), "smtp", json.RawMessage(input)); err == nil {
			t.Errorf("accepted invalid settings object %q", input)
		}
	}
}

func TestOrganizationSettingsPropagatesServerErrors(t *testing.T) {
	for _, method := range []string{"GET", "POST", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			c := newTestClient(t, route{method: method, path: "/directorysync/settings.json", handler: func(w http.ResponseWriter, r *http.Request) {
				writeAPIError(t, w, 403, "plugin unavailable or forbidden")
			}})
			var err error
			switch method {
			case "GET":
				_, err = c.GetOrganizationSettings(context.Background(), "directory-sync")
			case "POST":
				_, err = c.SetOrganizationSettings(context.Background(), "directory-sync", json.RawMessage(`{}`))
			case "DELETE":
				err = c.DeleteOrganizationSettings(context.Background(), "directory-sync", "")
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != 403 {
				t.Errorf("error=%v, want API 403", err)
			}
		})
	}
}

func TestOrganizationSettingsHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := newTestClient(t)
	if _, err := c.GetOrganizationSettings(ctx, "smtp"); !errors.Is(err, context.Canceled) {
		t.Errorf("error=%v, want canceled", err)
	}
}

func TestOrganizationSettingsPluginCapabilities(t *testing.T) {
	plugins := OrganizationSettingsPlugins()
	if len(plugins) != len(organizationSettingsRoutes) {
		t.Fatalf("plugin count %d", len(plugins))
	}
	var names []string
	for i, p := range plugins {
		want := organizationSettingsRoutes[i]
		names = append(names, p.Name)
		if p.Name != want.name || p.Readable != want.read || p.Writable != want.write || p.Deletable != want.delete || p.DeleteRequiresID != want.deleteID {
			t.Errorf("unexpected descriptor %+v", p)
		}
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("plugins not sorted: %v", names)
	}
	plugins[0].Name = "changed"
	if OrganizationSettingsPlugins()[0].Name == "changed" {
		t.Fatal("caller mutated plugin registry")
	}
}
