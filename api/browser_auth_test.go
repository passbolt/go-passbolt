package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestBrowserLoginImportsIndependentSessionAndChecksAccount(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "wrong account"}[wrong], func(t *testing.T) {
			client := newTestClientWithKey(t,
				route{method: "POST", path: "/browser-auth/exchange.json", handler: func(w http.ResponseWriter, r *http.Request) {
					var got BrowserGrant
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
						t.Error(err)
					}
					if got.Token != "grant" || got.Verifier != strings.Repeat("a", 43) {
						t.Errorf("unexpected exchange request: %#v", got)
					}
					http.SetCookie(w, &http.Cookie{Name: "passbolt_session", Value: "cli-session", Path: "/"})
					http.SetCookie(w, &http.Cookie{Name: "passbolt_mfa", Value: "cli-mfa", Path: "/"})
					writeAPIResponse(t, w, map[string]string{"user_id": "expected-user"})
				}},
				route{method: "GET", path: "/users/me.json", handler: func(w http.ResponseWriter, r *http.Request) {
					session, _ := r.Cookie("passbolt_session")
					mfa, _ := r.Cookie("passbolt_mfa")
					if session == nil || session.Value != "cli-session" || mfa == nil || mfa.Value != "cli-mfa" {
						t.Error("independent session not used")
					}
					id := "expected-user"
					if wrong {
						id = "other-user"
					}
					writeAPIResponse(t, w, User{ID: id})
				}},
				route{method: "GET", path: "/settings.json", handler: func(w http.ResponseWriter, r *http.Request) { writeAPIResponse(t, w, ServerSettingsResponse{}) }},
				route{method: "POST", path: "/auth/logout.json", handler: func(w http.ResponseWriter, r *http.Request) { writeAPIResponse(t, w, nil) }},
			)
			err := client.LoginWithBrowserGrant(bg(), BrowserGrant{Token: "grant", UserID: "expected-user", Verifier: strings.Repeat("a", 43)})
			if wrong {
				if err == nil {
					t.Fatal("accepted wrong account")
				}
				if client.sessionToken.Value != "" {
					t.Fatal("failed login retained session")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if client.userID != "expected-user" {
				t.Fatal("user not initialized")
			}
		})
	}
}
func TestBrowserLoginRejectsDebugAndMissingGrant(t *testing.T) {
	client := newTestClientWithKey(t)
	client.Debug = true
	if err := client.LoginWithBrowserGrant(bg(), BrowserGrant{Token: "secret"}); err == nil {
		t.Fatal("debug accepted")
	}
	client.Debug = false
	if err := client.LoginWithBrowserGrant(bg(), BrowserGrant{}); err == nil {
		t.Fatal("missing grant accepted")
	}
}
