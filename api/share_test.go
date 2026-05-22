package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The share endpoints exercise the SDK's most polymorphic
// deserialization: SearchAROs returns a flat array mixing User-shaped
// and Group-shaped objects. ARO's custom UnmarshalJSON distinguishes
// them by the presence of a "username" field — silent
// misclassification would produce unauthorized share grants.

func TestSearchAROs_DecodesMixedUsersAndGroups(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/share/search-aros.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			// Hand-crafted raw JSON so we can inject both shapes — a User
			// (has "username") and a Group (has "name" + "user_count") —
			// into a single array, mimicking the real server response.
			body := json.RawMessage(`[
				{"id":"` + validUUID + `","username":"alice"},
				{"id":"` + otherUUID + `","name":"Engineers","user_count":12}
			]`)
			env := APIResponse{
				Header: APIHeader{Status: "success", Code: 200},
				Body:   body,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(env)
		},
	})

	got, err := client.SearchAROs(bg(), SearchAROsOptions{FilterSearch: "ali"})
	if err != nil {
		t.Fatalf("SearchAROs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d AROs, want 2", len(got))
	}
	if got[0].Username != "alice" {
		t.Errorf("AROs[0] should be a User with username=alice, got %+v", got[0])
	}
	if got[1].Name != "Engineers" {
		t.Errorf("AROs[1] should be a Group named Engineers, got %+v", got[1])
	}
	if got[1].UserCount != 12 {
		t.Errorf("AROs[1].UserCount = %d, want 12", got[1].UserCount)
	}
}

// TestARO_MarshalJSON_DispatchesByUsernameField exercises the inverse
// path: when serializing an ARO we must emit ONE shape (User or
// Group), never both. Username presence is the discriminator. This
// guards against double-fields in the wire payload that would confuse
// the server.
func TestARO_MarshalJSON_DispatchesByUsernameField(t *testing.T) {
	t.Parallel()

	// User branch: Username is set → emit the User shape.
	userARO := ARO{User: User{ID: validUUID, Username: "alice"}}
	raw, err := json.Marshal(userARO)
	if err != nil {
		t.Fatalf("marshal user-shaped ARO: %v", err)
	}
	if !strings.Contains(string(raw), `"username":"alice"`) {
		t.Errorf("got %s, want it to marshal as a User", string(raw))
	}

	// Group branch: Username empty → emit the Group shape.
	groupARO := ARO{Group: Group{ID: otherUUID, Name: "Engineers"}}
	raw, err = json.Marshal(groupARO)
	if err != nil {
		t.Fatalf("marshal group-shaped ARO: %v", err)
	}
	if !strings.Contains(string(raw), `"name":"Engineers"`) {
		t.Errorf("got %s, want it to marshal as a Group", string(raw))
	}
	if strings.Contains(string(raw), `"username"`) {
		t.Errorf("group-shaped ARO should NOT emit a username field, got %s", string(raw))
	}
}

// TestShareFolder_WrapsPermissionsInFolder is the one share-endpoint
// test that catches a real shape bug (rather than a URL typo):
// ShareFolder takes a permissions slice but must wrap it in a Folder
// body so the server sees permissions nested under "permissions".
// Sending a bare slice would fail server-side schema validation with a
// confusing error.
func TestShareFolder_WrapsPermissionsInFolder(t *testing.T) {
	t.Parallel()

	var seen Folder
	_, client := newTestClient(t, route{
		method: "PUT", path: "/share/folder/" + validUUID + ".json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			readJSONBody(t, r, &seen)
			writeAPIResponse(t, w, nil)
		},
	})
	perms := []Permission{{ARO: "User", Type: 1}}
	if err := client.ShareFolder(bg(), validUUID, perms); err != nil {
		t.Fatalf("ShareFolder: %v", err)
	}
	if len(seen.Permissions) != 1 || seen.Permissions[0].Type != 1 {
		t.Errorf("seen = %+v, want one Permission with Type=1", seen)
	}
}
