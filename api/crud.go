package api

import (
	"context"
	"encoding/json"
)

// crud.go contains small generic helpers that capture the request/decode
// boilerplate shared by the entity CRUD methods (resources, users, groups,
// folders). The public Client methods remain thin, type-specific wrappers
// around these helpers so their signatures and behavior are unchanged.

// doList performs a GET on a collection endpoint and decodes the JSON array
// into a slice of T.
func doList[T any](ctx context.Context, c *Client, path string, opts interface{}) ([]T, error) {
	msg, err := c.DoCustomRequest(ctx, "GET", path, "v2", nil, opts)
	if err != nil {
		return nil, err
	}

	var result []T
	if err := json.Unmarshal(msg.Body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// doInto performs a request and decodes the JSON response body into a fresh T.
// It is used for single-entity GETs and for mutations whose request body type
// differs from the response type (e.g. updating a group with a GroupUpdate).
func doInto[T any](ctx context.Context, c *Client, method, path string, body, opts interface{}) (*T, error) {
	msg, err := c.DoCustomRequest(ctx, method, path, "v2", body, opts)
	if err != nil {
		return nil, err
	}

	var result T
	if err := json.Unmarshal(msg.Body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// doSave performs a create/update request and decodes the response back into
// the supplied body value, preserving any input fields the server does not
// echo. This matches the long-standing behavior of CreateX/UpdateX where the
// request and response share the same type.
func doSave[T any](ctx context.Context, c *Client, method, path string, body T) (*T, error) {
	msg, err := c.DoCustomRequest(ctx, method, path, "v2", body, nil)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(msg.Body, &body); err != nil {
		return nil, err
	}
	return &body, nil
}

// doDelete performs a DELETE request and discards the response body.
func doDelete(ctx context.Context, c *Client, path string) error {
	_, err := c.DoCustomRequest(ctx, "DELETE", path, "v2", nil, nil)
	return err
}
