package api

// Benchmarks for the PGP primitives in encryption.go. These are the hottest
// CPU paths in the SDK: every secret retrieval decrypts at least one message,
// and bulk listing fans this out across hundreds of resources. The pairing of
// BenchmarkDecryptMessage (asymmetric) with BenchmarkDecryptMessageWithSessionKey
// (symmetric fast path) makes the session-key-cache speedup measurable as a
// regression signal — see sessionkey_cache_test.go for the qualitative assertion.

import (
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// benchPayload is a ~256-byte string approximating a typical secret blob
// (password + description JSON). Sized so the crypto cost dominates over
// per-call overhead without being unrealistically large.
const benchPayload = "correct-horse-battery-staple-0123456789-abcdefghijklmnopqrstuvwxyz-" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ-the-quick-brown-fox-jumps-over-the-lazy-dog-" +
	"0123456789-supercalifragilisticexpialidocious-passbolt-secret-payload!!"

// sink defeats dead-code elimination: the compiler may not assume the result
// of an exported, side-effect-free call is unused if it escapes to a package
// global.
var (
	benchStringSink string
	benchErrSink    error
)

func BenchmarkEncryptMessage(b *testing.B) {
	_, client := newTestClientWithKey(b)

	b.ReportAllocs()
	for b.Loop() {
		benchStringSink, benchErrSink = client.EncryptMessage(benchPayload)
		if benchErrSink != nil {
			b.Fatalf("EncryptMessage: %v", benchErrSink)
		}
	}
}

// BenchmarkDecryptMessage measures the asymmetric decrypt path: every call
// copies the private key and performs a full PGP decryption.
func BenchmarkDecryptMessage(b *testing.B) {
	_, client := newTestClientWithKey(b)

	armored, err := client.EncryptMessage(benchPayload)
	if err != nil {
		b.Fatalf("EncryptMessage (setup): %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		benchStringSink, benchErrSink = client.DecryptMessage(armored)
		if benchErrSink != nil {
			b.Fatalf("DecryptMessage: %v", benchErrSink)
		}
	}
}

// BenchmarkDecryptMessageWithSessionKey measures the symmetric fast path. We
// run one asymmetric decrypt up front to recover the real session key bound to
// the ciphertext, then loop on the session-key decrypt only. Compare against
// BenchmarkDecryptMessage to quantify the cache win.
func BenchmarkDecryptMessageWithSessionKey(b *testing.B) {
	_, client := newTestClientWithKey(b)

	armored, err := client.EncryptMessage(benchPayload)
	if err != nil {
		b.Fatalf("EncryptMessage (setup): %v", err)
	}

	key, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		b.Fatalf("GetUserPrivateKeyCopy (setup): %v", err)
	}
	_, sessionKey, err := client.DecryptMessageWithPrivateKeyAndReturnSessionKey(key, armored)
	if err != nil {
		b.Fatalf("DecryptMessageWithPrivateKeyAndReturnSessionKey (setup): %v", err)
	}
	if sessionKey == nil {
		b.Fatal("setup: nil session key")
	}

	// DecryptMessageWithSessionKey clears the session key it is handed (via the
	// deferred ClearPrivateParams). In production the cache returns a fresh
	// clone per call for exactly this reason, so we mirror that by cloning from
	// a preserved original each iteration. The clone is a thin byte-slice wrap;
	// the asymmetric work was done once, up front.
	b.ReportAllocs()
	for b.Loop() {
		sk := crypto.NewSessionKeyFromToken(sessionKey.Key, sessionKey.Algo)
		benchStringSink, benchErrSink = client.DecryptMessageWithSessionKey(sk, armored)
		if benchErrSink != nil {
			b.Fatalf("DecryptMessageWithSessionKey: %v", benchErrSink)
		}
	}
}
