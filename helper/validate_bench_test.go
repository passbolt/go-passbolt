package helper

import (
	"testing"

	"github.com/passbolt/go-passbolt/api"
)

// These benchmarks measure the cache-hit path, which is what a large `list` actually pays: one
// schema resolve + compile per (slug, section), then a validate per resource. Before the unified
// cache, validateSecretData had no cache at all and ran a full jsonschema compile once per
// resource, so the secret benchmark is the one that documents the improvement.

var (
	benchMetadata = `{"name":"Stripe","username":"u","uris":["https://stripe.com"],` +
		`"description":"prod","object_type":"PASSBOLT_RESOURCE_METADATA","resource_type_id":"r"}`
	benchSecret = `{"object_type":"PASSBOLT_SECRET_DATA","password":"correct horse battery staple"}`
)

func BenchmarkValidateMetadata(b *testing.B) {
	rt := &api.ResourceType{Slug: "v5-default"}
	if err := validateMetadata(rt, benchMetadata); err != nil {
		b.Fatalf("setup: %v", err)
	}
	for b.Loop() {
		if err := validateMetadata(rt, benchMetadata); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateSecretData(b *testing.B) {
	rt := &api.ResourceType{Slug: "v5-default"}
	if err := validateSecretData(rt, benchSecret); err != nil {
		b.Fatalf("setup: %v", err)
	}
	for b.Loop() {
		if err := validateSecretData(rt, benchSecret); err != nil {
			b.Fatal(err)
		}
	}
}
