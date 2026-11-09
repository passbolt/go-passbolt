package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/passbolt/go-passbolt/api"
)

const groupTestID = "11111111-1111-1111-1111-111111111111"
const groupTestUser = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
const groupTestMembership = "33333333-3333-3333-3333-333333333333"

func groupClient(t *testing.T, handler http.HandlerFunc) *api.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := api.NewClient(srv.Client(), "test", srv.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func groupResponse(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"header": map[string]any{"status": "success", "code": 200}, "body": body}); err != nil {
		t.Fatal(err)
	}
}

func TestGetGroupMembershipLayouts(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		manager    bool
	}{
		{"legacy", `{"id":"` + groupTestID + `","name":"team","groups_users":[{"id":"` + groupTestMembership + `","user_id":"` + groupTestUser + `","is_admin":true,"user":{"id":"` + groupTestUser + `","username":"ada@example.com"}}]}`, true},
		{"camel", `{"id":"` + groupTestID + `","name":"team","users":[{"id":"` + groupTestUser + `","username":"ada@example.com","_joinData":{"id":"` + groupTestMembership + `","is_admin":false}}]}`, false},
		{"snake", `{"id":"` + groupTestID + `","name":"team","users":[{"id":"` + groupTestUser + `","username":"ada@example.com","_join_data":{"id":"` + groupTestMembership + `","is_admin":true}}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := groupClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/groups/"+groupTestID+".json" {
					t.Errorf("request=%s %s", r.Method, r.URL.Path)
				}
				groupResponse(t, w, json.RawMessage(tc.body))
			})
			name, members, err := GetGroup(context.Background(), c, groupTestID)
			if err != nil {
				t.Fatal(err)
			}
			if name != "team" || len(members) != 1 {
				t.Fatalf("name=%s members=%v", name, members)
			}
			m := members[0]
			if m.MembershipID != groupTestMembership || m.UserID != groupTestUser || m.Username != "ada@example.com" || m.IsGroupManager != tc.manager {
				t.Errorf("member=%+v", m)
			}
		})
	}
}

func TestGetGroupEmptyAndMissingMembershipData(t *testing.T) {
	for _, tc := range []struct {
		body    string
		wantErr bool
	}{{`{"id":"` + groupTestID + `","name":"empty","groups_users":[]}`, false}, {`{"id":"` + groupTestID + `","name":"empty","users":[]}`, false}, {`{"id":"` + groupTestID + `","name":"unknown"}`, true}} {
		c := groupClient(t, func(w http.ResponseWriter, r *http.Request) { groupResponse(t, w, json.RawMessage(tc.body)) })
		_, members, err := GetGroup(context.Background(), c, groupTestID)
		if (err != nil) != tc.wantErr {
			t.Errorf("body=%s err=%v", tc.body, err)
		}
		if !tc.wantErr && len(members) != 0 {
			t.Errorf("members=%v", members)
		}
	}
}

func TestUpdateGroupIsIdempotent(t *testing.T) {
	for _, op := range []GroupMembershipOperation{{UserID: groupTestUser, IsGroupManager: true}, {UserID: strings.ToUpper(groupTestUser), IsGroupManager: true}, {UserID: "44444444-4444-4444-4444-444444444444", Delete: true}} {
		calls := 0
		c := groupClient(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			if r.Method != "GET" {
				t.Errorf("unexpected mutation %s", r.Method)
			}
			groupResponse(t, w, map[string]any{"id": groupTestID, "name": "team", "groups_users": []map[string]any{{"id": groupTestMembership, "user_id": groupTestUser, "is_admin": true}}})
		})
		if err := UpdateGroup(context.Background(), c, groupTestID, "", []GroupMembershipOperation{op}); err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Errorf("calls=%d", calls)
		}
	}
}

func TestUpdateGroupVerifiesChanges(t *testing.T) {
	for _, mode := range []string{"success", "ignored", "missing-data", "delete", "empty-add"} {
		t.Run(mode, func(t *testing.T) {
			reads, updates, dryruns := 0, 0, 0
			c := groupClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.Path {
				case "GET /groups/" + groupTestID + ".json":
					reads++
					members := []map[string]any{{"id": groupTestMembership, "user_id": groupTestUser, "is_admin": true}}
					if mode == "empty-add" && reads == 1 || mode == "delete" && reads > 1 {
						members = []map[string]any{}
					}
					if reads > 1 && mode != "ignored" && mode != "delete" {
						members[0]["is_admin"] = false
					}
					body := map[string]any{"id": groupTestID, "name": "team", "groups_users": members}
					if mode == "missing-data" && reads > 1 {
						delete(body, "groups_users")
					}
					groupResponse(t, w, body)
				case "PUT /groups/" + groupTestID + "/dry-run.json":
					dryruns++
					groupResponse(t, w, map[string]any{"dry-run": map[string]any{}})
				case "PUT /groups/" + groupTestID + ".json":
					updates++
					var body struct {
						Changes []map[string]json.RawMessage `json:"groups_users"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if len(body.Changes) != 1 {
						t.Fatalf("changes=%v", body.Changes)
					}
					if mode != "delete" && string(body.Changes[0]["is_admin"]) != "false" {
						t.Errorf("is_admin=%s", body.Changes[0]["is_admin"])
					}
					groupResponse(t, w, map[string]any{})
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			})
			err := UpdateGroup(context.Background(), c, groupTestID, "", []GroupMembershipOperation{{UserID: groupTestUser, Delete: mode == "delete"}})
			wantErr := mode == "ignored" || mode == "missing-data"
			if (err != nil) != wantErr {
				t.Errorf("err=%v wantErr=%t", err, wantErr)
			}
			if reads != 2 || updates != 1 || dryruns != 1 {
				t.Errorf("reads=%d updates=%d dryruns=%d", reads, updates, dryruns)
			}
		})
	}
}

func TestUpdateGroupRejectsConflictingOperations(t *testing.T) {
	c := groupClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request before validation")
		http.NotFound(w, r)
	})
	err := UpdateGroup(context.Background(), c, groupTestID, "", []GroupMembershipOperation{{UserID: groupTestUser}, {UserID: groupTestUser, IsGroupManager: true}})
	if err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("err=%v", err)
	}
}

func TestUpdateGroupPreservesAPIError(t *testing.T) {
	c := groupClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"header":{"status":"error","code":403,"message":"forbidden"},"body":{}}`)
	})
	if err := UpdateGroup(context.Background(), c, groupTestID, "", nil); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("err=%v", err)
	}
}

func TestGetGroupRejectsIncompleteOrConflictingMemberships(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"missing-role", `{"groups_users":[{"id":"` + groupTestMembership + `","user_id":"` + groupTestUser + `"}]}`},
		{"null-role", `{"groups_users":[{"id":"` + groupTestMembership + `","user_id":"` + groupTestUser + `","is_admin":null}]}`},
		{"missing-membership-id", `{"groups_users":[{"user_id":"` + groupTestUser + `","is_admin":false}]}`},
		{"modern-missing-role", `{"users":[{"id":"` + groupTestUser + `","_joinData":{"id":"` + groupTestMembership + `"}}]}`},
		{"nested-user-mismatch", `{"groups_users":[{"id":"` + groupTestMembership + `","user_id":"` + groupTestUser + `","is_admin":false,"user":{"id":"` + groupTestID + `"}}]}`},
		{"group-mismatch", `{"groups_users":[{"id":"` + groupTestMembership + `","user_id":"` + groupTestUser + `","group_id":"` + groupTestUser + `","is_admin":false}]}`},
		{"join-group-mismatch", `{"users":[{"id":"` + groupTestUser + `","_joinData":{"id":"` + groupTestMembership + `","group_id":"` + groupTestUser + `","is_admin":false}}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body map[string]any
			if err := json.Unmarshal([]byte(tc.body), &body); err != nil {
				t.Fatal(err)
			}
			body["id"] = groupTestID
			body["name"] = "team"
			c := groupClient(t, func(w http.ResponseWriter, r *http.Request) { groupResponse(t, w, body) })
			if _, _, err := GetGroup(context.Background(), c, groupTestID); err == nil {
				t.Fatal("accepted incomplete or conflicting membership")
			}
		})
	}
}

func TestGetGroupMergesComplementaryLayouts(t *testing.T) {
	c := groupClient(t, func(w http.ResponseWriter, r *http.Request) {
		groupResponse(t, w, json.RawMessage(`{"id":"`+groupTestID+`","name":"team","groups_users":[{"user_id":"`+groupTestUser+`","user":{"username":"ada@example.com"}}],"users":[{"id":"`+groupTestUser+`","_joinData":{"id":"`+groupTestMembership+`","is_admin":false}}]}`))
	})
	_, members, err := GetGroup(context.Background(), c, groupTestID)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].MembershipID != groupTestMembership || members[0].Username != "ada@example.com" || members[0].IsGroupManager {
		t.Errorf("members=%v", members)
	}
}

func TestUpdateGroupRenameAndMixedVerification(t *testing.T) {
	for _, mode := range []string{"rename", "ignored-rename", "mixed", "missing-unchanged-role", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			reads, writes := 0, 0
			c := groupClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					reads++
					name := "team"
					if reads > 1 && mode == "rename" {
						name = "renamed"
					}
					members := []map[string]any{{"id": groupTestMembership, "user_id": groupTestUser, "is_admin": true}}
					if reads > 1 && (mode == "mixed" || mode == "missing-unchanged-role") {
						members = append(members, map[string]any{"id": "55555555-5555-5555-5555-555555555555", "user_id": "44444444-4444-4444-4444-444444444444", "is_admin": false})
					}
					if reads > 1 && mode == "missing-unchanged-role" {
						delete(members[0], "is_admin")
					}
					groupResponse(t, w, map[string]any{"id": groupTestID, "name": name, "groups_users": members})
					return
				}
				if strings.Contains(r.URL.Path, "dry-run") {
					groupResponse(t, w, map[string]any{"dry-run": map[string]any{}})
					return
				}
				writes++
				groupResponse(t, w, map[string]any{})
			})
			name := ""
			ops := []GroupMembershipOperation{{UserID: groupTestUser, IsGroupManager: true}}
			switch mode {
			case "rename", "ignored-rename":
				name = "renamed"
			case "mixed", "missing-unchanged-role":
				ops = append(ops, GroupMembershipOperation{UserID: "44444444-4444-4444-4444-444444444444"})
			case "duplicate":
				ops = append(ops, ops[0])
			}
			err := UpdateGroup(context.Background(), c, groupTestID, name, ops)
			wantErr := mode == "ignored-rename" || mode == "missing-unchanged-role"
			if (err != nil) != wantErr {
				t.Errorf("error=%v wantErr=%t", err, wantErr)
			}
			if mode == "duplicate" {
				if reads != 1 || writes != 0 {
					t.Errorf("unexpected duplicate writes")
				}
			} else if reads != 2 || writes != 1 {
				t.Errorf("reads=%d writes=%d", reads, writes)
			}
		})
	}
}

func TestUpdateGroupErrorsAtEachStage(t *testing.T) {
	for _, stage := range []string{"dry-run", "write", "verification"} {
		t.Run(stage, func(t *testing.T) {
			reads := 0
			c := groupClient(t, func(w http.ResponseWriter, r *http.Request) {
				fail := false
				if r.Method == "GET" {
					reads++
					fail = stage == "verification" && reads > 1
				} else if strings.Contains(r.URL.Path, "dry-run") {
					fail = stage == "dry-run"
				} else {
					fail = stage == "write"
				}
				if fail {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, `{"header":{"status":"error","code":403,"message":"forbidden"},"body":{}}`)
					return
				}
				if r.Method == "GET" {
					groupResponse(t, w, map[string]any{"id": groupTestID, "name": "team", "groups_users": []map[string]any{{"id": groupTestMembership, "user_id": groupTestUser, "is_admin": true}}})
				} else {
					groupResponse(t, w, map[string]any{"dry-run": map[string]any{}})
				}
			})
			if err := UpdateGroup(context.Background(), c, groupTestID, "", []GroupMembershipOperation{{UserID: groupTestUser}}); err == nil || !strings.Contains(err.Error(), "forbidden") {
				t.Errorf("err=%v", err)
			}
		})
	}
}

func TestGroupMembershipResponseUUIDCase(t *testing.T) {
	for _, both := range []bool{false, true} {
		c := groupClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Errorf("unexpected mutation %s", r.Method)
			}
			body := map[string]any{"id": groupTestID, "name": "team", "groups_users": []map[string]any{{"id": groupTestMembership, "user_id": strings.ToUpper(groupTestUser), "is_admin": true}}}
			if both {
				body["users"] = []map[string]any{{"id": groupTestUser, "_joinData": map[string]any{"id": groupTestMembership, "is_admin": true}}}
			}
			groupResponse(t, w, body)
		})
		_, members, err := GetGroup(context.Background(), c, groupTestID)
		if err != nil {
			t.Fatal(err)
		}
		if len(members) != 1 || members[0].UserID != groupTestUser {
			t.Errorf("members=%+v", members)
		}
		if err := UpdateGroup(context.Background(), c, groupTestID, "", []GroupMembershipOperation{{UserID: groupTestUser, IsGroupManager: true}}); err != nil {
			t.Fatal(err)
		}
	}
}
