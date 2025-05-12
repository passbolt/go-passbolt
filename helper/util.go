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
	return "", fmt.Errorf("Cannot Find Key for user id %v", userID)
}

func getMembershipByUserID(memberships []api.GroupMembership, userID string) (*api.GroupMembership, error) {
	for _, membership := range memberships {
		if membership.UserID == userID {
			return &membership, nil
		}
	}
	return nil, fmt.Errorf("Cannot Find Membership for user id %v", userID)
}

func getSecretByResourceID(secrets []api.Secret, resourceID string) (*api.Secret, error) {
	for _, secret := range secrets {
		if secret.ResourceID == resourceID {
			return &secret, nil
		}
	}
	return nil, fmt.Errorf("Cannot Find Secret for id %v", resourceID)
}
