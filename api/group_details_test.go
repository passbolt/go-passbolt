package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestGroupUserAcceptsJoinDataSpellings(t *testing.T) {
	for _, key := range []string{"_joinData", "_join_data"} {
		var user GroupUser
		if err := json.Unmarshal([]byte(`{"id":"`+validUUID+`","username":"ada@example.com","`+key+`":{"id":"`+otherUUID+`","is_admin":true}}`), &user); err != nil {
			t.Fatal(err)
		}
		if user.ID != validUUID || user.Username != "ada@example.com" || user.JoinData.ID != otherUUID || !user.JoinData.IsAdmin {
			t.Errorf("%s: %+v", key, user)
		}
	}
}

func TestGetGroupWithOptions(t *testing.T) {
	c := newTestClient(t, route{method: "GET", path: "/groups/" + validUUID + ".json", handler: func(w http.ResponseWriter, r *http.Request) {
		for _, key := range []string{"contain[users]", "contain[groups_users]", "contain[groups_users.user.profile]"} {
			if r.URL.Query().Get(key) != "true" {
				t.Errorf("missing %s in %s", key, r.URL.RawQuery)
			}
		}
		writeAPIResponse(t, w, Group{ID: validUUID, Name: "team", GroupUsers: []GroupMembership{}})
	}})
	g, err := c.GetGroupWithOptions(context.Background(), validUUID, &GetGroupsOptions{ContainUsers: true, ContainGroupsUsers: true, ContainGroupsUsersUserProfile: true})
	if err != nil {
		t.Fatal(err)
	}
	if g.ID != validUUID {
		t.Errorf("group=%+v", g)
	}
}

func TestGroupUserRejectsConflictingJoinIdentity(t *testing.T) {
	for _, field := range []string{"user_id", "group_id"} {
		var u GroupUser
		data := `{"id":"` + validUUID + `","_join_data":{"id":"` + otherUUID + `","is_admin":false,"` + field + `":"` + validUUID + `"},"_joinData":{"id":"` + otherUUID + `","is_admin":false,"` + field + `":"` + otherUUID + `"}}`
		if err := json.Unmarshal([]byte(data), &u); err == nil {
			t.Errorf("accepted conflicting %s", field)
		}
	}
}
