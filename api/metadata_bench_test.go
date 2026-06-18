package api

// Benchmarks for the V5 metadata decryption path (metadata.go) and the
// session-key cache accessors (client.go). Metadata decryption is the
// per-resource cost paid when listing V5 resources, so the cache-hit vs
// cache-miss spread directly bounds list latency at scale.

import "testing"

// benchMetadata approximates a V5 resource metadata JSON blob.
const benchMetadata = `{"object_type":"PASSBOLT_RESOURCE_METADATA",` +
	`"resource_type_id":"a28a04cd-6f53-518a-967c-9a8ba6c8f1f8",` +
	`"name":"Production database root","username":"root",` +
	`"uris":["https://db.internal.example.com:5432"],` +
	`"description":"Primary Postgres cluster — rotate quarterly"}`

// benchMetadataKeyID is an arbitrary stable cache key for the metadata-key
// session-key cache.
const benchMetadataKeyID = "33333333-3333-3333-3333-333333333333"

// BenchmarkDecryptMetadata measures the cache-miss baseline: full asymmetric
// decryption with no session-key cache (empty key ID disables caching).
func BenchmarkDecryptMetadata(b *testing.B) {
	_, client := newTestClientWithKey(b)

	key, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		b.Fatalf("GetUserPrivateKeyCopy (setup): %v", err)
	}
	armored, err := client.EncryptMetadata(key, benchMetadata)
	if err != nil {
		b.Fatalf("EncryptMetadata (setup): %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		benchStringSink, benchErrSink = client.DecryptMetadata(key, armored)
		if benchErrSink != nil {
			b.Fatalf("DecryptMetadata: %v", benchErrSink)
		}
	}
}

// BenchmarkDecryptMetadataWithKeyID measures the cache-hit path. We seed the
// cache with the REAL session key bound to the ciphertext (a placeholder key
// would fail the symmetric decrypt and silently fall back to the asymmetric
// path, making this identical to BenchmarkDecryptMetadata). The loop then
// exercises the symmetric fast path the cache is meant to deliver.
func BenchmarkDecryptMetadataWithKeyID(b *testing.B) {
	_, client := newTestClientWithKey(b)

	key, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		b.Fatalf("GetUserPrivateKeyCopy (setup): %v", err)
	}
	armored, err := client.EncryptMetadata(key, benchMetadata)
	if err != nil {
		b.Fatalf("EncryptMetadata (setup): %v", err)
	}

	// Recover the real session key once and seed the cache so the benchmark
	// hits the symmetric path on every iteration.
	_, sessionKey, err := client.DecryptMessageWithPrivateKeyAndReturnSessionKey(key, armored)
	if err != nil {
		b.Fatalf("DecryptMessageWithPrivateKeyAndReturnSessionKey (setup): %v", err)
	}
	client.SetSessionKeyByMetadataKeyID(benchMetadataKeyID, sessionKey)

	b.ReportAllocs()
	for b.Loop() {
		benchStringSink, benchErrSink = client.DecryptMetadataWithKeyID(benchMetadataKeyID, key, armored)
		if benchErrSink != nil {
			b.Fatalf("DecryptMetadataWithKeyID: %v", benchErrSink)
		}
	}
}

// BenchmarkSessionKeyCache_GetSet tracks the raw map + mutex overhead of the
// session-key cache accessors, isolated from any crypto. A deterministic
// placeholder key is fine here — nothing decrypts.
func BenchmarkSessionKeyCache_GetSet(b *testing.B) {
	_, client := newTestClient(b)
	sk := sessionKeyForTest()

	b.ReportAllocs()
	for b.Loop() {
		client.SetSessionKeyByMetadataKeyID(benchMetadataKeyID, sk)
		if client.GetSessionKeyByMetadataKeyID(benchMetadataKeyID) == nil {
			b.Fatal("expected cached session key, got nil")
		}
	}
}
