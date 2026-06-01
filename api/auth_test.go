package api

import (
	"net/http"
	"sync/atomic"
	"testing"
)

// Auth tests cover the small but security-critical surface: session
// status checks and Logout. The full Login flow (GPG challenge-response)
// is left to integration tests because the four-leg auth dance against
// a real Passbolt server is what gives confidence — a mock would just
// regurgitate the data we feed it.

// CheckSession is a fire-and-forget probe used by long-lived CLI
// sessions to decide if they need to re-authenticate. Any HTTP error
// (network, 4xx, 5xx) must translate to false; only a successful
// response means we're still authenticated.
func TestCheckSession_TrueOnSuccessFromServer(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/auth/is-authenticated.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, map[string]bool{"authenticated": true})
		},
	})
	if got := client.CheckSession(bg()); !got {
		t.Error("CheckSession = false, want true")
	}
}

// The negative case: a 401 from the server is the documented
// "you're not logged in" signal, and CheckSession must return false.
func TestCheckSession_FalseOnServerError(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/auth/is-authenticated.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIError(t, w, 401, "Authentication required")
		},
	})
	if got := client.CheckSession(bg()); got {
		t.Error("CheckSession = true, want false")
	}
}

// TestLogout_WipesPrivateKeyAndCaches is the central security
// guarantee of Logout: after it returns, the client must hold no
// material that could be used to decrypt anything. We pre-seed the
// session-key cache and the user's private key, call Logout, then
// verify both have been wiped. A regression that forgot to call
// ClearCache or ClearPrivateParams would surface here.
func TestLogout_WipesPrivateKeyAndCaches(t *testing.T) {
	t.Parallel()

	var hit atomic.Bool
	_, client := newTestClientWithKey(t, route{
		method: "POST", path: "/auth/logout.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			hit.Store(true)
			writeAPIResponse(t, w, map[string]string{})
		},
	})

	// Pre-seed the session-key cache to verify Logout clears it.
	client.SetSessionKeyByMetadataKeyID("mk-1", sessionKeyForTest())

	if err := client.Logout(bg()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if !hit.Load() {
		t.Error("server never received the logout request")
	}
	if _, err := client.GetUserPrivateKeyCopy(); err == nil {
		t.Error("private key still present after Logout — sensitive material left in memory")
	}
	if got := client.GetSessionKeyByMetadataKeyID("mk-1"); got != nil {
		t.Errorf("session-key cache not cleared: %+v", got)
	}
}

// If the server returns an error during logout we still want to
// surface it so the caller can retry; silently swallowing would mask
// genuine connectivity problems.
func TestLogout_PropagatesServerError(t *testing.T) {
	t.Parallel()

	_, client := newTestClientWithKey(t, route{
		method: "POST", path: "/auth/logout.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIError(t, w, 500, "server down")
		},
	})
	if err := client.Logout(bg()); err == nil {
		t.Fatal("expected error propagated from server, got nil")
	}
}
