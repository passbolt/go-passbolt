//go:build go1.27

// These tests need Go 1.27, so they are skipped entirely on the 1.26 toolchain
// the SDK still supports. The dependency is httptest.NewTestServer: a synctest
// bubble only advances its virtual clock once every goroutine in it is durably
// blocked, and a goroutine waiting on a real socket never is, so a server
// holding a loopback port deadlocks the bubble instead. NewTestServer serves
// over an in-memory network, which is why it is the only httptest server usable
// inside one - and it landed in 1.27.
//
// The build constraint also raises this file's language version to 1.27, which
// is what lets it use that API at all while go.mod declares 1.26.8.
//
// The cost is that MFA retry coverage is missing on a 1.26 toolchain. CI runs
// 1.27, so it is covered where it counts; anyone verifying the 1.26 floor gets
// a compiling package and one fewer test. helper/mfa.go itself is plain Go and
// builds on both.

package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/passbolt/go-passbolt/api"
)

// The retry loop in AddMFACallbackTOTP sleeps between failed TOTP attempts, which
// made it effectively untestable: asserting on the backoff meant really sleeping.
// These tests run inside a testing/synctest bubble, where time.Sleep advances a
// virtual clock instantly, so the retry count and the delay between attempts are
// both observable in zero wall-clock time. See the build constraint above for why
// the mock server has to be httptest.NewTestServer.

// mfaTestSecret is the RFC 6238 Appendix B shared key, reused from totp_test.go's
// rfc6238SharedKey. Any valid base32 secret works; this one is already covered by
// the vector tests, so a failure here is the callback's fault, not the TOTP maths.
const mfaTestSecret = rfc6238SharedKey

// mfaAttempt records one request the callback made to the TOTP endpoint.
type mfaAttempt struct {
	code    string        // the TOTP code submitted
	elapsed time.Duration // virtual time since the bubble started
}

// mfaRecorder is the mock TOTP endpoint. It records every attempt and fails the
// first failFirst of them, so a test can pin both the retry count and the backoff.
type mfaRecorder struct {
	t          *testing.T
	start      time.Time
	failFirst  int  // fail this many attempts before succeeding; -1 fails them all
	omitCookie bool // accept the code but answer without the passbolt_mfa cookie

	mu       sync.Mutex
	attempts []mfaAttempt
}

func (m *mfaRecorder) handler(w http.ResponseWriter, r *http.Request) {
	var body api.MFAChallengeResponse
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		m.t.Errorf("decoding MFA challenge response body: %v", err)
		return
	}

	m.mu.Lock()
	m.attempts = append(m.attempts, mfaAttempt{code: body.TOTP, elapsed: time.Since(m.start)})
	n := len(m.attempts)
	m.mu.Unlock()

	if m.failFirst < 0 || n <= m.failFirst {
		// A plain "error" envelope becomes an *api.APIError, which is the signal
		// AddMFACallbackTOTP reads as "wrong code, try again". Deliberately not
		// code 403 with an /mfa/verify/error.json URL: the client would take that
		// for a fresh MFA challenge and re-enter the callback.
		writeMFAEnvelope(m.t, w, api.APIHeader{Status: "error", Code: 400, Message: "invalid code"})
		return
	}
	if !m.omitCookie {
		http.SetCookie(w, &http.Cookie{Name: "passbolt_mfa", Value: "mfa-session-token"})
	}
	writeMFAEnvelope(m.t, w, api.APIHeader{Status: "success", Code: 200})
}

func (m *mfaRecorder) recorded() []mfaAttempt {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mfaAttempt(nil), m.attempts...)
}

// writeMFAEnvelope emits the Passbolt response envelope with the given header.
func writeMFAEnvelope(t *testing.T, w http.ResponseWriter, header api.APIHeader) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	env := api.APIResponse{Header: header, Body: json.RawMessage(`{}`)}
	if err := json.NewEncoder(w).Encode(env); err != nil {
		t.Errorf("encoding MFA envelope: %v", err)
	}
}

// newMFATestClient starts an in-memory mock server exposing only the TOTP verify
// endpoint and returns a Client aimed at it. Any other path fails the test.
func newMFATestClient(t *testing.T, h http.HandlerFunc) *api.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mfa/verify/totp.json", h)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to MFA mock server: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})

	srv := httptest.NewTestServer(t, mux)
	// srv.Client() must precede reading srv.URL: on an in-memory server the first
	// Client call is what starts the fake net and populates URL.
	httpClient := srv.Client()
	c, err := api.NewClient(httpClient, "go-passbolt-mfa-test", srv.URL, "", "")
	if err != nil {
		t.Fatalf("api.NewClient: %v", err)
	}
	return c
}

// mfaChallengeResponse builds the APIResponse the client hands to MFACallback when
// the server demands MFA. A non-empty totp provider is what makes the callback
// proceed rather than bail.
func mfaChallengeResponse(t *testing.T, totpProvider string) *api.APIResponse {
	t.Helper()
	body, err := json.Marshal(api.MFAChallenge{
		Provider: api.MFAProviders{TOTP: totpProvider},
	})
	if err != nil {
		t.Fatalf("marshaling MFA challenge: %v", err)
	}
	return &api.APIResponse{
		Header: api.APIHeader{Status: "error", Code: 403, URL: "/mfa/verify/error.json"},
		Body:   body,
	}
}

// TestAddMFACallbackTOTP_RetriesThenSucceeds pins the happy retry path: two
// rejected codes, then acceptance. It asserts the attempt count, that the
// configured delay elapsed between consecutive attempts, and that the
// passbolt_mfa cookie is what comes back.
func TestAddMFACallbackTOTP_RetriesThenSucceeds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			retrys     = uint(3)
			retryDelay = 5 * time.Second
			failures   = 2
		)

		rec := &mfaRecorder{t: t, start: time.Now(), failFirst: failures}
		c := newMFATestClient(t, rec.handler)
		AddMFACallbackTOTP(c, retrys, retryDelay, 0, mfaTestSecret)

		cookie, err := c.MFACallback(context.Background(), c, mfaChallengeResponse(t, "/mfa/verify/totp"))
		if err != nil {
			t.Fatalf("MFACallback: unexpected error: %v", err)
		}
		if cookie.Name != "passbolt_mfa" {
			t.Errorf("cookie.Name = %q, want %q", cookie.Name, "passbolt_mfa")
		}
		if cookie.Value != "mfa-session-token" {
			t.Errorf("cookie.Value = %q, want %q", cookie.Value, "mfa-session-token")
		}

		attempts := rec.recorded()
		if len(attempts) != failures+1 {
			t.Fatalf("made %d attempts, want %d (stops as soon as one is accepted)", len(attempts), failures+1)
		}
		// One retryDelay per rejected attempt, and none after the accepted one.
		for i, a := range attempts {
			want := time.Duration(i) * retryDelay
			if a.elapsed != want {
				t.Errorf("attempt %d at %v, want %v", i+1, a.elapsed, want)
			}
		}
	})
}

// TestAddMFACallbackTOTP_ExhaustsRetries pins the failure path: the callback must
// try exactly retrys+1 times, report that count, and then give up with an error.
//
// Both a zero and a non-zero retrys are covered on purpose. A single retrys=2 case
// cannot tell "retrys+1" apart from a hardcoded 3, which is how the error message
// came to claim "3 times" for every configuration.
func TestAddMFACallbackTOTP_ExhaustsRetries(t *testing.T) {
	const retryDelay = 10 * time.Second

	for _, retrys := range []uint{0, 2} {
		t.Run(fmt.Sprintf("retrys=%d", retrys), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rec := &mfaRecorder{t: t, start: time.Now(), failFirst: -1}
				c := newMFATestClient(t, rec.handler)
				AddMFACallbackTOTP(c, retrys, retryDelay, 0, mfaTestSecret)

				_, err := c.MFACallback(context.Background(), c, mfaChallengeResponse(t, "/mfa/verify/totp"))
				if err == nil {
					t.Fatal("MFACallback: got nil error, want failure after exhausting retries")
				}
				if want := fmt.Sprintf("after %d attempts", retrys+1); !strings.Contains(err.Error(), want) {
					t.Errorf("error is %q, want it to report %q", err, want)
				}

				attempts := rec.recorded()
				// retrys+1 = the initial attempt plus each configured retry.
				if len(attempts) != int(retrys)+1 {
					t.Fatalf("made %d attempts, want %d", len(attempts), int(retrys)+1)
				}
				for i, a := range attempts {
					want := time.Duration(i) * retryDelay
					if a.elapsed != want {
						t.Errorf("attempt %d at %v, want %v", i+1, a.elapsed, want)
					}
				}
				// One delay between attempts and none after the last one, so the
				// callback returns the moment the final code is rejected.
				if total, want := time.Since(rec.start), time.Duration(retrys)*retryDelay; total != want {
					t.Errorf("callback returned after %v, want %v (it must not sleep after the last attempt)", total, want)
				}
			})
		})
	}
}

// TestAddMFACallbackTOTP_AppliesOffset checks that the offset argument actually
// reaches GenerateOTPCode. A 60s offset crosses two 30s TOTP steps from the
// bubble's fixed start time, so the submitted code must be the offset one and
// must differ from the un-offset code.
func TestAddMFACallbackTOTP_AppliesOffset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const offset = 60 * time.Second

		start := time.Now()
		rec := &mfaRecorder{t: t, start: start, failFirst: 0}
		c := newMFATestClient(t, rec.handler)
		AddMFACallbackTOTP(c, 0, time.Second, offset, mfaTestSecret)

		if _, err := c.MFACallback(context.Background(), c, mfaChallengeResponse(t, "/mfa/verify/totp")); err != nil {
			t.Fatalf("MFACallback: unexpected error: %v", err)
		}

		attempts := rec.recorded()
		if len(attempts) != 1 {
			t.Fatalf("made %d attempts, want 1", len(attempts))
		}

		wantCode, err := GenerateOTPCode(mfaTestSecret, start.Add(offset))
		if err != nil {
			t.Fatalf("GenerateOTPCode: %v", err)
		}
		if attempts[0].code != wantCode {
			t.Errorf("submitted code %q, want %q (offset not applied)", attempts[0].code, wantCode)
		}

		unshifted, err := GenerateOTPCode(mfaTestSecret, start)
		if err != nil {
			t.Fatalf("GenerateOTPCode: %v", err)
		}
		if wantCode == unshifted {
			t.Fatalf("offset %v does not change the code (%q) — test cannot detect a dropped offset", offset, wantCode)
		}
	})
}

// TestAddMFACallbackTOTP_NoTOTPProvider covers the early bail when the server
// offers MFA but no TOTP provider: the callback must fail without touching the
// verify endpoint at all.
func TestAddMFACallbackTOTP_NoTOTPProvider(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rec := &mfaRecorder{t: t, start: time.Now(), failFirst: -1}
		c := newMFATestClient(t, rec.handler)
		AddMFACallbackTOTP(c, 3, time.Second, 0, mfaTestSecret)

		// Empty totp provider.
		_, err := c.MFACallback(context.Background(), c, mfaChallengeResponse(t, ""))
		if err == nil {
			t.Fatal("MFACallback: got nil error, want failure when no TOTP provider is offered")
		}
		if n := len(rec.recorded()); n != 0 {
			t.Errorf("made %d requests, want 0 — must bail before trying any code", n)
		}
	})
}

// TestAddMFACallbackTOTP_MissingCookie covers a server that accepts the code but
// does not set passbolt_mfa. The callback must report that rather than returning
// a zero cookie as if it had succeeded.
func TestAddMFACallbackTOTP_MissingCookie(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// failFirst: 0 accepts the first code; omitCookie answers without setting
		// passbolt_mfa.
		rec := &mfaRecorder{t: t, start: time.Now(), failFirst: 0, omitCookie: true}
		c := newMFATestClient(t, rec.handler)
		AddMFACallbackTOTP(c, 3, time.Second, 0, mfaTestSecret)

		_, err := c.MFACallback(context.Background(), c, mfaChallengeResponse(t, "/mfa/verify/totp"))
		if err == nil {
			t.Fatal("MFACallback: got nil error, want failure when passbolt_mfa cookie is absent")
		}
		// A missing cookie is not a wrong code, so it must not burn the retries.
		if n := len(rec.recorded()); n != 1 {
			t.Errorf("made %d requests, want 1: a missing cookie must not be retried", n)
		}
	})
}
