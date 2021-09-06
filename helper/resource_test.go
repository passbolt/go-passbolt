package helper

import (
	"context"
	"testing"
)

func TestResourceCreate(t *testing.T) {
	id, err := CreateResource(context.TODO(), client, "", "name", "username", "https://url.lan", "password123", "a password description")
	if err != nil {
		t.Fatalf("Creating Resource %v", err)
	}

	_, name, username, uri, password, description, err := GetResource(context.TODO(), client, id)
	if err != nil {
		t.Fatalf("Getting Resource %v", err)
	}

	equal(t, "Name", name, "name")
	equal(t, "Username", username, "username")
	equal(t, "URI", uri, "https://url.lan")
	equal(t, "Password", password, "password123")
	equal(t, "Description", description, "a password description")
}

func equal(t *testing.T, name, a, b string) {
	if a != b {
		t.Fatalf("Value %v is %v instead of %v", name, a, b)
	}
}
