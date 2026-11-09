package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestGroupDemotionSendsExplicitFalse(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		name, path := "update", "/groups/"+validUUID+".json"
		if dryRun {
			name, path = "dry-run", "/groups/"+validUUID+"/dry-run.json"
		}
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, route{method: "PUT", path: path, handler: func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Changes []map[string]json.RawMessage `json:"groups_users"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if len(body.Changes) != 1 {
					t.Fatalf("changes = %v", body.Changes)
				}
				if got := string(body.Changes[0]["is_admin"]); got != "false" {
					t.Errorf("is_admin = %q, want explicit false", got)
				}
				if got := string(body.Changes[0]["id"]); got != `"`+otherUUID+`"` {
					t.Errorf("membership id = %s", got)
				}
				writeAPIResponse(t, w, map[string]any{})
			}})
			update := GroupUpdate{GroupChanges: []GroupMembership{{ID: otherUUID, IsAdmin: false}}}
			var err error
			if dryRun {
				_, err = client.UpdateGroupDryRun(context.Background(), validUUID, update)
			} else {
				_, err = client.UpdateGroup(context.Background(), validUUID, update)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
