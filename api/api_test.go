package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// DoCustomRequestV5 is the single funnel every entity method passes
// through. The tests in this file exercise its central state machine:
//
//   - happy path (status=success)        → APIResponse returned
//   - status=error                       → typed *APIError with code
//   - status=<anything else>             → typed *APIError (unknown status)
//   - malformed JSON / network error     → wrapped error
//   - context cancellation               → wraps context.Canceled
//   - CSRF cookie capture on first response, sent back on next request
//   - MFA challenge handling             → retry once on success,
//                                          fail otherwise
//
// Because every higher-level entity test mocks DoCustomRequestV5
// indirectly via httptest, regressions in this layer manifest
// everywhere. We exercise it directly here so failures are localized.

func TestDoCustomRequestV5_Success(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/ping.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, map[string]string{"pong": "yes"})
		},
	})

	res, err := client.DoCustomRequestV5(bg(), "GET", "/ping.json", nil, nil)
	if err != nil {
		t.Fatalf("DoCustomRequestV5: %v", err)
	}
	if res.Header.Status != "success" {
		t.Errorf("Header.Status = %q, want %q", res.Header.Status, "success")
	}
	if !strings.Contains(string(res.Body), `"pong":"yes"`) {
		t.Errorf("Body = %q, want it to contain pong:yes", string(res.Body))
	}
}

// TestDoCustomRequestV5_ErrorStatusReturnsAPIError pins both the typed
// error (callers branch on apiErr.StatusCode) AND the legacy sentinel
// (errors.Is(err, ErrAPIResponseErrorStatusCode)). Existing code in the
// helper/ package still uses the sentinel form for backward compat;
// dropping it would silently break consumers.
func TestDoCustomRequestV5_ErrorStatusReturnsAPIError(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/forbidden.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIError(t, w, 403, "Forbidden")
		},
	})

	_, err := client.DoCustomRequestV5(bg(), "GET", "/forbidden.json", nil, nil)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %v is not *APIError", err)
	}
	if apiErr.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
	if apiErr.Message != "Forbidden" {
		t.Errorf("Message = %q, want %q", apiErr.Message, "Forbidden")
	}
	if !errors.Is(err, ErrAPIResponseErrorStatusCode) {
		t.Errorf("legacy sentinel ErrAPIResponseErrorStatusCode must still match (backward compat)")
	}
}

// Unknown status string (anything not "success" or "error") also
// surfaces as *APIError, but it matches the *unknown* sentinel rather
// than the *error* one. Helper code in the CLI uses this distinction
// to print a different message ("server returned unrecognized status").
func TestDoCustomRequestV5_UnknownStatusReturnsAPIError(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/weird.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			env := APIResponse{
				Header: APIHeader{Status: "elsewhere", Code: 418, Message: "teapot"},
			}
			writeRawJSON(t, w, env)
		},
	})

	_, err := client.DoCustomRequestV5(bg(), "GET", "/weird.json", nil, nil)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %v is not *APIError", err)
	}
	if apiErr.StatusCode != 418 || apiErr.Message != "teapot" {
		t.Errorf("got %+v, want code=418 message=teapot", apiErr)
	}
	if !errors.Is(err, ErrAPIResponseUnknownStatusCode) {
		t.Errorf("unknown-status sentinel ErrAPIResponseUnknownStatusCode must match")
	}
}

// If the server returns non-JSON or truncated JSON, the SDK must NOT
// crash and must NOT silently return zero values — both would mask
// real production issues like a proxy injecting HTML error pages.
func TestDoCustomRequestV5_MalformedJSONBody(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/broken.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{not valid json"))
		},
	})

	_, err := client.DoCustomRequestV5(bg(), "GET", "/broken.json", nil, nil)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "Parse JSON") {
		t.Errorf("error %q should mention JSON parsing", err.Error())
	}
}

// A network-level failure (here simulated by closing the server) must
// be wrapped with the "doing Request" prefix so callers can grep error
// chains for the cause.
func TestDoCustomRequestV5_NetworkError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	client, err := NewClient(nil, "", srv.URL, "", "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	srv.Close() // force the next request to fail at the TCP layer.

	_, err = client.DoCustomRequestV5(bg(), "GET", "/anything.json", nil, nil)
	if err == nil {
		t.Fatal("expected network error, got nil")
	}
	if !strings.Contains(err.Error(), "doing Request") {
		t.Errorf("error %q should be wrapped with 'doing Request'", err.Error())
	}
}

// Context cancellation must surface as a context error, not a generic
// HTTP failure, so callers can branch on context.Canceled /
// context.DeadlineExceeded to decide whether to retry.
func TestDoCustomRequestV5_ContextCancellation(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/slow.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		},
	})

	ctx, cancel := context.WithCancel(bg())
	cancel() // pre-cancel — never actually reaches the server.

	_, err := client.DoCustomRequestV5(ctx, "GET", "/slow.json", nil, nil)
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err %v should wrap context.Canceled", err)
	}
}

// TestDoCustomRequestV5_CapturesCSRFCookieOnFirstResponse covers the
// CSRF lifecycle: on the very first response (during Login), the
// server's Set-Cookie header carries csrfToken, and we must remember
// it so subsequent requests can send it back in BOTH the header AND
// the cookie. The two halves are tested separately (here and in the
// next test) because they have different code paths.
func TestDoCustomRequestV5_CapturesCSRFCookieOnFirstResponse(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/seed.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "csrfToken", Value: "abc123"})
			writeAPIResponse(t, w, map[string]string{})
		},
	})

	if _, err := client.DoCustomRequestV5(bg(), "GET", "/seed.json", nil, nil); err != nil {
		t.Fatalf("seed call: %v", err)
	}
	if client.csrfToken.Name != "csrfToken" || client.csrfToken.Value != "abc123" {
		t.Errorf("csrfToken = %+v, want Name=csrfToken Value=abc123", client.csrfToken)
	}
}

// Counterpart to the previous test: once the cookie was captured, the
// SDK must echo it back on every subsequent request. The server-side
// Passbolt requires BOTH the X-CSRF-Token header AND the csrfToken
// cookie to match — missing either fails its CSRF check.
func TestDoCustomRequestV5_SendsCSRFHeaderAndCookieOnSubsequentRequests(t *testing.T) {
	t.Parallel()

	var seenHeader, seenCookie atomic.Value
	seenHeader.Store("")
	seenCookie.Store("")

	_, client := newTestClient(t,
		route{
			method: "GET", path: "/seed.json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "csrfToken", Value: "xyz"})
				writeAPIResponse(t, w, map[string]string{})
			},
		},
		route{
			method: "GET", path: "/follow.json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				seenHeader.Store(r.Header.Get("X-CSRF-Token"))
				if c, err := r.Cookie("csrfToken"); err == nil {
					seenCookie.Store(c.Value)
				}
				writeAPIResponse(t, w, map[string]string{})
			},
		},
	)

	if _, err := client.DoCustomRequestV5(bg(), "GET", "/seed.json", nil, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := client.DoCustomRequestV5(bg(), "GET", "/follow.json", nil, nil); err != nil {
		t.Fatalf("follow: %v", err)
	}
	if got := seenHeader.Load().(string); got != "xyz" {
		t.Errorf("X-CSRF-Token header on follow request = %q, want %q", got, "xyz")
	}
	if got := seenCookie.Load().(string); got != "xyz" {
		t.Errorf("csrfToken cookie on follow request = %q, want %q", got, "xyz")
	}
}

// TestDoCustomRequestV5_RetriesAfterMFACallbackSucceeds covers the MFA
// retry state machine. On the first call the server returns the MFA
// challenge (code 403 with URL suffix /mfa/verify/error.json); the SDK
// must invoke MFACallback, capture the cookie it returns, set
// mfaToken, and retry the original request. We assert all three:
// callback fired, server saw 2 calls, mfaToken is set.
func TestDoCustomRequestV5_RetriesAfterMFACallbackSucceeds(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	_, client := newTestClient(t, route{
		method: "GET", path: "/protected.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			n := callCount.Add(1)
			if n == 1 {
				writeMFAChallenge(t, w)
				return
			}
			writeAPIResponse(t, w, map[string]string{"ok": "yes"})
		},
	})

	var callbackInvoked atomic.Bool
	client.MFACallback = func(ctx context.Context, c *Client, res *APIResponse) (http.Cookie, error) {
		callbackInvoked.Store(true)
		return http.Cookie{Name: "passbolt_mfa", Value: "verified"}, nil
	}

	res, err := client.DoCustomRequestV5(bg(), "GET", "/protected.json", nil, nil)
	if err != nil {
		t.Fatalf("DoCustomRequestV5: %v", err)
	}
	if !callbackInvoked.Load() {
		t.Error("MFA callback was not invoked")
	}
	if callCount.Load() != 2 {
		t.Errorf("expected 2 server calls (challenge + retry), got %d", callCount.Load())
	}
	if !strings.Contains(string(res.Body), `"ok":"yes"`) {
		t.Errorf("Body = %q, want it to contain ok:yes", string(res.Body))
	}
	if client.mfaToken.Value != "verified" {
		t.Errorf("mfaToken.Value = %q, want %q after callback", client.mfaToken.Value, "verified")
	}
}

// If the MFA callback errors (e.g. the user cancels the prompt), the
// error must propagate verbatim so the CLI can show it to the user.
func TestDoCustomRequestV5_FailsWhenMFACallbackErrors(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/protected.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeMFAChallenge(t, w)
		},
	})
	client.MFACallback = func(ctx context.Context, c *Client, res *APIResponse) (http.Cookie, error) {
		return http.Cookie{}, fmt.Errorf("user declined MFA")
	}

	_, err := client.DoCustomRequestV5(bg(), "GET", "/protected.json", nil, nil)
	if err == nil {
		t.Fatal("expected error from MFA callback, got nil")
	}
	if !strings.Contains(err.Error(), "user declined MFA") {
		t.Errorf("error %q should propagate callback message", err.Error())
	}
}

// Two MFA challenges in a row means the callback returned a token that
// didn't satisfy the server. We must NOT retry indefinitely — the
// firstTime guard in DoCustomRequest is what prevents an infinite loop
// here. This test would loop forever if that guard regressed.
func TestDoCustomRequestV5_FailsWhenMFAChallengeRepeats(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/protected.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeMFAChallenge(t, w)
		},
	})
	client.MFACallback = func(ctx context.Context, c *Client, res *APIResponse) (http.Cookie, error) {
		return http.Cookie{Name: "passbolt_mfa", Value: "broken"}, nil
	}

	_, err := client.DoCustomRequestV5(bg(), "GET", "/protected.json", nil, nil)
	if err == nil {
		t.Fatal("expected error after two MFA challenges in a row, got nil")
	}
	if !errors.Is(err, ErrMFAFailed) {
		t.Errorf("err should wrap ErrMFAFailed, got %v", err)
	}
}

// If the server demands MFA but the consumer forgot to install a
// callback, we must return ErrMFACallbackMissing so the CLI can print
// a useful "enable interactive-totp" hint.
func TestDoCustomRequestV5_FailsWhenMFAChallengedButCallbackMissing(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/protected.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeMFAChallenge(t, w)
		},
	})
	// MFACallback intentionally left nil.

	_, err := client.DoCustomRequestV5(bg(), "GET", "/protected.json", nil, nil)
	if !errors.Is(err, ErrMFACallbackMissing) {
		t.Errorf("err = %v, want ErrMFACallbackMissing", err)
	}
}

// TestDoCustomRequestV5_SendsJSONBodyWithCorrectHeaders pins the
// request shape the Passbolt server expects:
//   - Content-Type: application/json (server rejects others)
//   - Accept: application/json (so it returns JSON, not HTML)
//   - User-Agent: the constructor default
//   - Body: properly JSON-serialized
//
// A single missing header here would silently break the entire SDK
// against the real server.
func TestDoCustomRequestV5_SendsJSONBodyWithCorrectHeaders(t *testing.T) {
	t.Parallel()

	type payload struct {
		Name string `json:"name"`
	}
	var (
		gotContentType, gotAccept, gotUA string
		gotBody                          payload
	)
	_, client := newTestClient(t, route{
		method: "POST", path: "/echo.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			gotContentType = r.Header.Get("Content-Type")
			gotAccept = r.Header.Get("Accept")
			gotUA = r.Header.Get("User-Agent")
			readJSONBody(t, r, &gotBody)
			writeAPIResponse(t, w, map[string]string{})
		},
	})

	if _, err := client.DoCustomRequestV5(bg(), "POST", "/echo.json", payload{Name: "hello"}, nil); err != nil {
		t.Fatalf("DoCustomRequestV5: %v", err)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", gotAccept)
	}
	if gotUA != "goPassboltClient/1.0" {
		t.Errorf("User-Agent = %q, want default goPassboltClient/1.0", gotUA)
	}
	if gotBody.Name != "hello" {
		t.Errorf("body.Name = %q, want %q", gotBody.Name, "hello")
	}
}

// TestDoCustomRequestV5_SerialisesQueryOptions verifies the
// go-querystring tag conventions used throughout the SDK. Passbolt's
// CakePHP backend insists on bracket syntax (filter[search],
// filter[has-id][]) — getting this wrong silently drops filters.
func TestDoCustomRequestV5_SerialisesQueryOptions(t *testing.T) {
	t.Parallel()

	var gotQuery string
	_, client := newTestClient(t, route{
		method: "GET", path: "/list.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.RawQuery
			writeAPIResponse(t, w, []string{})
		},
	})

	type opts struct {
		Search string `url:"filter[search],omitempty"`
		Limit  int    `url:"limit,omitempty"`
	}
	if _, err := client.DoCustomRequestV5(bg(), "GET", "/list.json", nil, opts{Search: "abc", Limit: 5}); err != nil {
		t.Fatalf("DoCustomRequestV5: %v", err)
	}
	if !strings.Contains(gotQuery, "filter%5Bsearch%5D=abc") {
		t.Errorf("query %q missing filter[search]=abc", gotQuery)
	}
	if !strings.Contains(gotQuery, "limit=5") {
		t.Errorf("query %q missing limit=5", gotQuery)
	}
}

// The deprecated DoCustomRequest takes a `version` parameter that's now
// silently ignored. We assert the wrapper still reaches the underlying
// V5 implementation so legacy callers don't break during the deprecation
// window.
func TestDoCustomRequest_DeprecatedWrapperDelegates(t *testing.T) {
	t.Parallel()

	_, client := newTestClient(t, route{
		method: "GET", path: "/delegated.json",
		handler: func(w http.ResponseWriter, r *http.Request) {
			writeAPIResponse(t, w, map[string]string{"ok": "1"})
		},
	})

	res, err := client.DoCustomRequest(bg(), "GET", "/delegated.json", "v2", nil, nil)
	if err != nil {
		t.Fatalf("DoCustomRequest: %v", err)
	}
	if !strings.Contains(string(res.Body), `"ok":"1"`) {
		t.Errorf("Body = %q, want ok:1", string(res.Body))
	}
}

// writeRawJSON encodes v with no envelope, used only by tests that need
// to emit an exact APIResponse shape (e.g. an unknown status string)
// rather than going through writeAPIResponse which always sets
// status=success.
func writeRawJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("encode: %v", err)
	}
}
