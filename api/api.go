package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// APIResponse is the Struct representation of a Json Response
type APIResponse struct {
	Header APIHeader       `json:"header"`
	Body   json.RawMessage `json:"body"`
}

// APIHeader is the Struct representation of the Header of a APIResponse
type APIHeader struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Servertime int    `json:"servertime"`
	Action     string `json:"action"`
	Message    string `json:"message"`
	URL        string `json:"url"`
	Code       int    `json:"code"`
}

// DoCustomRequest Executes a Custom Request and returns a APIResponse
//
// Deprecated: DoCustomRequest is deprecated. Use DoCustomRequestV5 instead
func (c *Client) DoCustomRequest(ctx context.Context, method, path, version string, body interface{}, opts interface{}) (*APIResponse, error) {
	_, response, err := c.DoCustomRequestAndReturnRawResponse(ctx, method, path, version, body, opts)
	return response, err
}

// DoCustomRequestV5 Executes a Custom Request and returns a APIResponse
func (c *Client) DoCustomRequestV5(ctx context.Context, method, path string, body interface{}, opts interface{}) (*APIResponse, error) {
	_, response, err := c.DoCustomRequestAndReturnRawResponseV5(ctx, method, path, body, opts)
	return response, err
}

// DoCustomRequestAndReturnRawResponse Executes a Custom Request and returns a APIResponse and the Raw HTTP Response
//
// Deprecated: DoCustomRequestAndReturnRawResponse is deprecated. Use DoCustomRequestAndReturnRawResponseV5 instead
func (c *Client) DoCustomRequestAndReturnRawResponse(ctx context.Context, method, path, version string, body interface{}, opts interface{}) (*http.Response, *APIResponse, error) {
	// version is no longer used and is ignored.
	return c.DoCustomRequestAndReturnRawResponseV5(ctx, method, path, body, opts)
}

func (c *Client) DoCustomRequestAndReturnRawResponseV5(ctx context.Context, method, path string, body interface{}, opts interface{}) (*http.Response, *APIResponse, error) {
	firstTime := true
start:
	u, err := generateURL(*c.baseURL, path, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("generating Path: %w", err)
	}

	req, err := c.newRequest(method, u, body)
	if err != nil {
		return nil, nil, fmt.Errorf("creating New Request: %w", err)
	}

	var res APIResponse
	r, err := c.do(ctx, req, &res)
	if err != nil {
		return r, &res, fmt.Errorf("doing Request: %w", err)
	}

	// Because of MFA i need to do the csrf token stuff here
	if c.csrfToken.Name == "" {
		for _, cookie := range r.Cookies() {
			if cookie.Name == "csrfToken" {
				c.csrfToken = *cookie
			}
		}
	}

	switch res.Header.Status {
	case "success":
		return r, &res, nil
	case "error":
		if res.Header.Code == 403 && strings.HasSuffix(res.Header.URL, "/mfa/verify/error.json") {
			if !firstTime {
				// if we are here this probably means that the MFA callback is broken, to prevent a infinite loop lets error here
				return r, &res, fmt.Errorf("%w: got MFA challenge twice in a row, is your MFA callback broken? bailing to prevent loop", ErrMFAFailed)
			}
			if c.MFACallback != nil {
				c.mfaToken, err = c.MFACallback(ctx, c, &res)
				if err != nil {
					return r, &res, fmt.Errorf("handling MFA callback: %w", err)
				}
				// ok, we got the MFA challenge and the callback presumably handled it so we can retry the original request
				firstTime = false
				goto start
			} else {
				return r, &res, ErrMFACallbackMissing
			}
		}
		return r, &res, &APIError{StatusCode: res.Header.Code, Message: res.Header.Message, Body: string(res.Body)}
	default:
		return r, &res, &APIError{StatusCode: res.Header.Code, Message: res.Header.Message, Body: string(res.Body)}
	}
}
