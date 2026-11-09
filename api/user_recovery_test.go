package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestRecoverUserRequest(t *testing.T) {
	c := newTestClient(t, route{method: "POST", path: "/users/recover.json", handler: func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		readJSONBody(t, r, &body)
		if len(body) != 1 || body["username"] != "ada@example.com" {
			t.Errorf("body = %#v", body)
		}
		writeAPIResponse(t, w, nil)
	}})
	if err := c.RecoverUser(context.Background(), "ada@example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverUserRejectsBlankUsername(t *testing.T) {
	c := newTestClient(t)
	for _, username := range []string{"", " \t\n"} {
		if err := c.RecoverUser(context.Background(), username); err == nil {
			t.Errorf("accepted username %q", username)
		}
	}
}

func TestRecoverUserPropagatesAPIError(t *testing.T) {
	c := newTestClient(t, route{method: "POST", path: "/users/recover.json", handler: func(w http.ResponseWriter, r *http.Request) { writeAPIError(t, w, 400, "invalid username") }})
	err := c.RecoverUser(context.Background(), "ada@example.com")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 400 {
		t.Errorf("error = %v, want API 400", err)
	}
}
