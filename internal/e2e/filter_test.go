//go:build integration

package e2e

// Server-side list filters (#81).

import (
	"context"
	"slices"
	"testing"

	"github.com/passbolt/go-passbolt/api"
	"github.com/passbolt/go-passbolt/helper"
)

func TestListFilters(t *testing.T) {
	if client == nil {
		t.SkipNow()
	}
	ctx := context.Background()

	newUser := func(email, first string) string {
		t.Helper()
		u, err := pb.CreateUser(ctx, email, first, "Filter", "user", email)
		if err != nil {
			t.Fatalf("create user %s: %v", email, err)
		}
		// Runs after the group cleanups.
		t.Cleanup(func() {
			if err := client.DeleteUser(context.Background(), u.UserID); err != nil {
				t.Logf("delete user %s (cleanup): %v", email, err)
			}
		})
		return u.UserID
	}
	a := newUser("filter-a@passbolt.com", "A")
	b := newUser("filter-b@passbolt.com", "B")
	c := newUser("filter-c@passbolt.com", "C")

	newGroup := func(name string, ops ...helper.GroupMembershipOperation) string {
		t.Helper()
		id, err := helper.CreateGroup(ctx, client, name, ops)
		if err != nil {
			t.Fatalf("create group %s: %v", name, err)
		}
		t.Cleanup(func() {
			if err := helper.DeleteGroup(context.Background(), client, id); err != nil {
				t.Logf("delete group %s (cleanup): %v", name, err)
			}
		})
		return id
	}
	// g1: A manages, B member. g2: B manages, C member. g3: A and B manage.
	g1 := newGroup("filter-g1",
		helper.GroupMembershipOperation{UserID: a, IsGroupManager: true},
		helper.GroupMembershipOperation{UserID: b})
	g2 := newGroup("filter-g2",
		helper.GroupMembershipOperation{UserID: b, IsGroupManager: true},
		helper.GroupMembershipOperation{UserID: c})
	g3 := newGroup("filter-g3",
		helper.GroupMembershipOperation{UserID: a, IsGroupManager: true},
		helper.GroupMembershipOperation{UserID: b, IsGroupManager: true})

	// Several ids match groups that have all of them.
	groupCases := []struct {
		name string
		opts api.GetGroupsOptions
		want []string
	}{
		{"has-users one", api.GetGroupsOptions{FilterHasUsers: []string{c}}, []string{g2}},
		{"has-users several", api.GetGroupsOptions{FilterHasUsers: []string{a, b}}, []string{g1, g3}},
		{"has-managers one", api.GetGroupsOptions{FilterHasManagers: []string{b}}, []string{g2, g3}},
		{"has-managers several", api.GetGroupsOptions{FilterHasManagers: []string{a, b}}, []string{g3}},
	}
	for _, tc := range groupCases {
		t.Run(tc.name, func(t *testing.T) {
			groups, err := client.GetGroups(ctx, &tc.opts)
			if err != nil {
				t.Fatalf("GetGroups: %v", err)
			}
			got := make([]string, 0, len(groups))
			for _, g := range groups {
				got = append(got, g.ID)
			}
			assertSameIDs(t, got, tc.want)
		})
	}

	t.Run("has-groups", func(t *testing.T) {
		users, err := client.GetUsers(ctx, &api.GetUsersOptions{FilterHasGroup: []string{g2}})
		if err != nil {
			t.Fatalf("GetUsers: %v", err)
		}
		got := make([]string, 0, len(users))
		for _, u := range users {
			got = append(got, u.ID)
		}
		assertSameIDs(t, got, []string{b, c})
	})

	// Set on every user when the contain is honored.
	t.Run("missing_metadata_key_ids contain", func(t *testing.T) {
		users, err := client.GetUsers(ctx, &api.GetUsersOptions{MissingMetadataKeyIDs: true})
		if err != nil {
			t.Fatalf("GetUsers: %v", err)
		}
		if len(users) == 0 {
			t.Fatal("GetUsers returned no users")
		}
		for _, u := range users {
			if u.MissingMetadataKeyIDs == nil {
				t.Errorf("user %s: MissingMetadataKeyIDs not returned", u.Username)
			}
		}
	})
}

func assertSameIDs(t *testing.T, got, want []string) {
	t.Helper()
	got, want = slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))
	if !slices.Equal(got, want) {
		t.Errorf("got ids %v, want %v", got, want)
	}
}
