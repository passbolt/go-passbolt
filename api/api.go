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
func (c *Client) DoCustomRequest(ctx context.Context, method, path, version string, body interface{}, opts interface{}) (*APIResponse, error) {
	_, response, err := c.DoCustomRequestAndReturnRawResponse(ctx, method, path, version, body, opts)
	return response, err
}

// DoCustomRequestAndReturnRawResponse Executes a Custom Request and returns a APIResponse and the Raw HTTP Response
func (c *Client) DoCustomRequestAndReturnRawResponse(ctx context.Context, method, path, version string, body interface{}, opts interface{}) (*http.Response, *APIResponse, error) {
	firstTime := true
start:
	u, err := generateURL(*c.baseURL, path, version, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("Generating Path: %w", err)
	}

	req, err := c.newRequest(method, u, body)
	if err != nil {
		return nil, nil, fmt.Errorf("Creating New Request: %w", err)
	}

	var res APIResponse
	r, err := c.do(ctx, req, &res)
	if err != nil {
		return r, &res, fmt.Errorf("Doing Request: %w", err)
	}

	// Because of MFA i need to do the csrf token stuff here
	if c.csrfToken.Name == "" {
		for _, cookie := range r.Cookies() {
			if cookie.Name == "csrfToken" {
				c.csrfToken = *cookie
			}
		}
	}

	if res.Header.Status == "success" {
		return r, &res, nil
	} else if res.Header.Status == "error" {
		if res.Header.Code == 403 && strings.HasSuffix(res.Header.URL, "/mfa/verify/error.json") {
			if !firstTime {
				// if we are here this probably means that the MFA callback is broken, to prevent a infinite loop lets error here
				return r, &res, fmt.Errorf("Got MFA challenge twice in a row, is your MFA Callback broken? Bailing to prevent loop...:")
			}
			if c.MFACallback != nil {
				c.mfaToken, err = c.MFACallback(ctx, c, &res)
				if err != nil {
					return r, &res, fmt.Errorf("MFA Callback: %w", err)
				}
				// ok, we got the MFA challenge and the callback presumably handled it so we can retry the original request
				firstTime = false
				goto start
			} else {
				return r, &res, fmt.Errorf("Got MFA Challenge but the MFA callback is not defined")
			}
		}
		return r, &res, fmt.Errorf("%w: Message: %v, Body: %v", ErrAPIResponseErrorStatusCode, res.Header.Message, string(res.Body))
	} else {
		return r, &res, fmt.Errorf("%w: Message: %v, Body: %v", ErrAPIResponseUnknownStatusCode, res.Header.Message, string(res.Body))
	}
}
