package helper

import (
	"errors"
	"testing"

	"github.com/passbolt/go-passbolt/api"
)

// Tests for util.go list-search helpers. These functions are not
// glamorous, but they each wrap their miss case in a typed sentinel
// (ErrKeyNotFound, ErrMembershipNotFound, ErrSecretNotFound) that
// consumers branch on with errors.Is. A regression that returned a
// bare fmt.Errorf would silently break those consumers.

func TestGetPublicKeyByUserID(t *testing.T) {
	t.Parallel()

	users := []api.User{
		{ID: "user-1", GPGKey: &api.GPGKey{ArmoredKey: "key-1"}},
		{ID: "user-2", GPGKey: &api.GPGKey{ArmoredKey: "key-2"}},
	}

	t.Run("hit returns armored key", func(t *testing.T) {
		t.Parallel()
		got, err := getPublicKeyByUserID("user-2", users)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "key-2" {
			t.Errorf("got %q, want %q", got, "key-2")
		}
	})

	t.Run("miss wraps ErrKeyNotFound", func(t *testing.T) {
		t.Parallel()
		_, err := getPublicKeyByUserID("user-missing", users)
		if !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("err = %v, want wrap of ErrKeyNotFound", err)
		}
	})
}

func TestGetMembershipByUserID(t *testing.T) {
	t.Parallel()

	memberships := []api.GroupMembership{
		{ID: "m-1", UserID: "user-1", IsAdmin: false},
		{ID: "m-2", UserID: "user-2", IsAdmin: true},
	}

	t.Run("hit returns pointer to entry", func(t *testing.T) {
		t.Parallel()
		got, err := getMembershipByUserID(memberships, "user-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ID != "m-2" || !got.IsAdmin {
			t.Errorf("got %+v, want m-2 with IsAdmin=true", got)
		}
	})

	t.Run("miss wraps ErrMembershipNotFound", func(t *testing.T) {
		t.Parallel()
		_, err := getMembershipByUserID(memberships, "user-missing")
		if !errors.Is(err, ErrMembershipNotFound) {
			t.Errorf("err = %v, want wrap of ErrMembershipNotFound", err)
		}
	})
}

func TestGetSecretByResourceID(t *testing.T) {
	t.Parallel()

	secrets := []api.Secret{
		{ID: "s-1", ResourceID: "r-1", Data: "data-1"},
		{ID: "s-2", ResourceID: "r-2", Data: "data-2"},
	}

	t.Run("hit returns pointer to entry", func(t *testing.T) {
		t.Parallel()
		got, err := getSecretByResourceID(secrets, "r-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ID != "s-2" || got.Data != "data-2" {
			t.Errorf("got %+v, want s-2 with data-2", got)
		}
	})

	t.Run("miss wraps ErrSecretNotFound", func(t *testing.T) {
		t.Parallel()
		_, err := getSecretByResourceID(secrets, "r-missing")
		if !errors.Is(err, ErrSecretNotFound) {
			t.Errorf("err = %v, want wrap of ErrSecretNotFound", err)
		}
	})
}
