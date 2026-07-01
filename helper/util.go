package helper

import (
	"fmt"

	"github.com/passbolt/go-passbolt/api"
)

// findBy returns a pointer to the first element matching pred. If none match it
// returns notFound wrapped with key, matching the long-standing "%w: %v" format
// of the lookup helpers below.
func findBy[T any](items []T, pred func(T) bool, notFound error, key string) (*T, error) {
	for i := range items {
		if pred(items[i]) {
			return &items[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %v", notFound, key)
}

func getPublicKeyByUserID(userID string, Users []api.User) (string, error) {
	user, err := findBy(Users, func(u api.User) bool { return u.ID == userID }, ErrKeyNotFound, userID)
	if err != nil {
		return "", err
	}
	return user.GPGKey.ArmoredKey, nil
}

func getMembershipByUserID(memberships []api.GroupMembership, userID string) (*api.GroupMembership, error) {
	return findBy(memberships, func(m api.GroupMembership) bool { return m.UserID == userID }, ErrMembershipNotFound, userID)
}

func getSecretByResourceID(secrets []api.Secret, resourceID string) (*api.Secret, error) {
	return findBy(secrets, func(s api.Secret) bool { return s.ResourceID == resourceID }, ErrSecretNotFound, resourceID)
}
