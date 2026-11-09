package helper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/passbolt/go-passbolt/api"
)

func TestUpdateGroupReencryptsSharedSecretsAndVerifies(t *testing.T) {
	key, err := crypto.PGP().KeyGeneration().AddUserId("owner", "owner@example.com").New().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ownerPrivate, err := key.Armor()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := crypto.PGP().KeyGeneration().AddUserId("recipient", "recipient@example.com").New().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipientPrivate, err := recipient.Armor()
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic, err := recipient.GetArmoredPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	decryptor, err := api.NewClient(nil, "test", "https://unused.example", recipientPrivate, "")
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext string
	reads, updates := 0, 0
	resourceID := "44444444-4444-4444-4444-444444444444"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /groups/" + groupTestID + ".json":
			reads++
			members := []map[string]any{}
			if reads > 1 {
				members = append(members, map[string]any{"id": groupTestMembership, "user_id": groupTestUser, "is_admin": false})
			}
			groupResponse(t, w, map[string]any{"id": groupTestID, "name": "team", "groups_users": members})
		case "PUT /groups/" + groupTestID + "/dry-run.json":
			groupResponse(t, w, map[string]any{"dry-run": map[string]any{"SecretsNeeded": []map[string]any{{"Secret": map[string]any{"resource_id": resourceID, "user_id": groupTestUser}}}, "Secrets": []map[string]any{{"secret": []map[string]any{{"resource_id": resourceID, "data": ciphertext}}}}}})
		case "GET /users.json":
			groupResponse(t, w, []map[string]any{{"id": groupTestUser, "gpgkey": map[string]any{"armored_key": recipientPublic}}})
		case "PUT /groups/" + groupTestID + ".json":
			updates++
			var update api.GroupUpdate
			if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
				t.Fatal(err)
			}
			if len(update.Secrets) != 1 {
				t.Fatalf("secrets=%v", update.Secrets)
			}
			secret := update.Secrets[0]
			if secret.UserID != groupTestUser || secret.ResourceID != resourceID {
				t.Errorf("unexpected secret target %+v", secret)
			}
			plaintext, err := decryptor.DecryptMessage(secret.Data)
			if err != nil {
				t.Fatal(err)
			}
			if plaintext != "shared-password" {
				t.Errorf("plaintext=%q", plaintext)
			}
			groupResponse(t, w, map[string]any{})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	owner, err := api.NewClient(srv.Client(), "test", srv.URL, ownerPrivate, "")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err = owner.EncryptMessage("shared-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := UpdateGroup(context.Background(), owner, groupTestID, "", []GroupMembershipOperation{{UserID: groupTestUser}}); err != nil {
		t.Fatal(err)
	}
	if reads != 2 || updates != 1 {
		t.Errorf("reads=%d updates=%d", reads, updates)
	}
}
