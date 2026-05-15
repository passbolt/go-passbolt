package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestNewClient_RefusesCrossHostRedirect verifies that the http.Client built
// by NewClient refuses to follow a redirect to a host different from the
// configured Passbolt base URL. This guards against custom headers (notably
// X-CSRF-Token) being replayed to an attacker-controlled host, which the Go
// stdlib does not strip on cross-host redirects.
func TestNewClient_RefusesCrossHostRedirect(t *testing.T) {
	var redirectTargetHit atomic.Bool

	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(redirectTarget.Close)

	passboltServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL+"/exfil", http.StatusFound)
	}))
	t.Cleanup(passboltServer.Close)

	client, err := NewClient(nil, "", passboltServer.URL, "", "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, passboltServer.URL+"/auth/login.json", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	resp, err := client.httpClient.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatalf("expected cross-host redirect to be refused, got nil error")
	}
	if !strings.Contains(err.Error(), "cross-host redirect") {
		t.Errorf("error %q does not mention cross-host redirect", err.Error())
	}
	if redirectTargetHit.Load() {
		t.Errorf("redirect target was reached; the cross-host redirect was followed")
	}
}

// TestNewClient_AllowsSameHostRedirect verifies that same-host redirects are
// still followed, so legitimate server-side path rewrites do not break.
func TestNewClient_AllowsSameHostRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/end", http.StatusFound)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client, err := NewClient(nil, "", server.URL, "", "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, server.URL+"/start", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		t.Fatalf("same-host redirect should succeed, got error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if !strings.HasSuffix(resp.Request.URL.Path, "/end") {
		t.Errorf("expected final URL to end with /end, got %q", resp.Request.URL.Path)
	}
}
