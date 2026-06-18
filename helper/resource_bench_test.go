//go:build integration

package helper

// Integration benchmarks for the high-level resource helpers, run by
// `make bench-integration` against the ephemeral Passbolt booted in TestMain.
// These measure the full round-trip — encrypt + HTTP + (for Get) fetch +
// decrypt — so they capture real end-to-end cost, not just local crypto. The
// Makefile pins -benchtime=10x to keep iteration counts sane against a live
// server.

import (
	"context"
	"fmt"
	"testing"
)

// BenchmarkCreateResource measures a full create round-trip: metadata/secret
// encryption plus the create API call. Names are made unique per iteration so
// repeated runs don't collide on the server.
func BenchmarkCreateResource(b *testing.B) {
	ctx := context.Background()
	i := 0

	b.ReportAllocs()
	for b.Loop() {
		name := fmt.Sprintf("bench-create-%d", i)
		i++
		_, err := CreateResource(ctx, client, "", name, "username", "https://url.lan", "password123", "benchmark resource")
		if err != nil {
			b.Fatalf("CreateResource: %v", err)
		}
	}
}

// BenchmarkGetResource measures a full fetch + decrypt round-trip. One resource
// is created up front; the loop repeatedly retrieves and decrypts it.
func BenchmarkGetResource(b *testing.B) {
	ctx := context.Background()

	id, err := CreateResource(ctx, client, "", "bench-get", "username", "https://url.lan", "password123", "benchmark resource")
	if err != nil {
		b.Fatalf("CreateResource (setup): %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, _, _, _, _, _, err := GetResource(ctx, client, id); err != nil {
			b.Fatalf("GetResource: %v", err)
		}
	}
}
