package helper

import (
	"fmt"

	"github.com/passbolt/go-passbolt/api"
)

func getPublicKeyByUserID(userID string, Users []api.User) (string, error) {
	for _, user := range Users {
		if user.ID == userID {
			return user.GPGKey.ArmoredKey, nil
		}
	}
	return "", fmt.Errorf("%w: %v", ErrKeyNotFound, userID)
}

func getMembershipByUserID(memberships []api.GroupMembership, userID string) (*api.GroupMembership, error) {
	for _, membership := range memberships {
		if membership.UserID == userID {
			return &membership, nil
		}
	}
	return nil, fmt.Errorf("%w: %v", ErrMembershipNotFound, userID)
}

func getSecretByResourceID(secrets []api.Secret, resourceID string) (*api.Secret, error) {
	for _, secret := range secrets {
		if secret.ResourceID == resourceID {
			return &secret, nil
		}
	}
	return nil, fmt.Errorf("%w: %v", ErrSecretNotFound, resourceID)
}
