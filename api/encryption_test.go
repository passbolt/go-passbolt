package api

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// Encryption tests cover the api/ layer's PGP primitives. The two
// foundational properties we verify here are:
//
//  1. Round-trip integrity: encrypt(plaintext) → decrypt → plaintext.
//     Any regression in armoring, signing, or session-key handling would
//     break secret retrieval for every user.
//
//  2. Failure modes are typed errors: callers branch on ErrNoPrivateKey,
//     so we must NOT silently degrade to a generic error when the client
//     has been logged out.

// TestEncryptDecryptMessage_RoundTrip verifies the basic happy path: a
// message encrypted with the client's own key can be decrypted back. The
// armored prefix check guards against a regression that returns the raw
// (binary) PGP message — which would silently break the server side that
// expects armored input.
func TestEncryptDecryptMessage_RoundTrip(t *testing.T) {
	t.Parallel()

	client := newTestClientWithKey(t)

	want := "hello world"
	armored, err := client.EncryptMessage(want)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if !strings.Contains(armored, "BEGIN PGP MESSAGE") {
		t.Errorf("encrypted output does not look armored: %q", armored)
	}

	got, err := client.DecryptMessage(armored)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch: got %q, want %q", got, want)
	}
}

// Encryption without a key must fail with the typed ErrNoPrivateKey
// rather than crashing on nil pointer access. Callers (esp. the CLI)
// branch on this sentinel to prompt for login.
func TestEncryptMessage_FailsWithoutPrivateKey(t *testing.T) {
	t.Parallel()

	client := newTestClient(t) // no key
	_, err := client.EncryptMessage("anything")
	if !errors.Is(err, ErrNoPrivateKey) {
		t.Errorf("err = %v, want ErrNoPrivateKey", err)
	}
}

// Same as above but on the decrypt side. Logout zeroes the key; any
// subsequent decrypt attempt must surface this distinctly so consumers
// can re-authenticate.
func TestDecryptMessage_FailsWithoutPrivateKey(t *testing.T) {
	t.Parallel()

	client := newTestClient(t)
	_, err := client.DecryptMessage("-----BEGIN PGP MESSAGE-----\ngarbage\n-----END PGP MESSAGE-----")
	if !errors.Is(err, ErrNoPrivateKey) {
		t.Errorf("err = %v, want ErrNoPrivateKey", err)
	}
}

// Malformed PGP input must surface as an error rather than crashing or
// returning the input verbatim.
func TestDecryptMessage_RejectsMalformedCiphertext(t *testing.T) {
	t.Parallel()

	client := newTestClientWithKey(t)
	_, err := client.DecryptMessage("not a PGP message")
	if err == nil {
		t.Fatal("expected error for malformed ciphertext")
	}
}

// TestEncryptMessageWithKey_RoundTripUsingExternalRecipient verifies the
// "encrypt to an arbitrary recipient" path used by ShareResource (where
// the SDK must encrypt the secret to each new ARO's public key, not the
// caller's own). Reusing the same keypair as both signer and recipient
// keeps the test self-contained.
func TestEncryptMessageWithKey_RoundTripUsingExternalRecipient(t *testing.T) {
	t.Parallel()

	client := newTestClientWithKey(t)

	recipient, err := crypto.NewKeyFromArmored(testPGPPublic(t))
	if err != nil {
		t.Fatalf("parse recipient key: %v", err)
	}

	want := "secret payload"
	armored, err := client.EncryptMessageWithKey(recipient, want)
	if err != nil {
		t.Fatalf("EncryptMessageWithKey: %v", err)
	}
	got, err := client.DecryptMessage(armored)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestEncryptMessageWithKeyAndSigner_DualSignatureVerifies is the core
// correctness property this function exists for: a message encrypted with
// an extra signing key must carry TWO independently verifiable signatures
// (the user's own, plus the extra key's) rather than one signature
// overwriting the other. This is what shared v5 metadata needs so that
// other clients (e.g. the ansible lookup plugin) can verify it was signed
// by the metadata key, regardless of which user wrote it.
func TestEncryptMessageWithKeyAndSigner_DualSignatureVerifies(t *testing.T) {
	t.Parallel()

	client := newTestClientWithKey(t)
	extraKey := generateTestKey(t, "Shared Metadata Key", "metadata@example.com")

	want := "shared secret payload"
	armored, err := client.EncryptMessageWithKeyAndSigner(extraKey, extraKey, want)
	if err != nil {
		t.Fatalf("EncryptMessageWithKeyAndSigner: %v", err)
	}

	verifiers, err := crypto.NewKeyRing(extraKey)
	if err != nil {
		t.Fatalf("build verify keyring: %v", err)
	}
	userPublic, err := crypto.NewKeyFromArmored(testPGPPublic(t))
	if err != nil {
		t.Fatalf("parse user public key: %v", err)
	}
	if err := verifiers.AddKey(userPublic); err != nil {
		t.Fatalf("add user key to verify keyring: %v", err)
	}

	decHandle, err := crypto.PGP().Decryption().DecryptionKey(extraKey).VerificationKeys(verifiers).New()
	if err != nil {
		t.Fatalf("new decryptor: %v", err)
	}
	res, err := decHandle.Decrypt([]byte(armored), crypto.Armor)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if res.String() != want {
		t.Errorf("round-trip mismatch: got %q, want %q", res.String(), want)
	}
	if err := res.SignatureError(); err != nil {
		t.Errorf("selected signature failed verification: %v", err)
	}

	verifiedFingerprints := map[string]bool{}
	for _, sig := range res.Signatures {
		if sig.SignatureError == nil && sig.SignedBy != nil {
			verifiedFingerprints[sig.SignedBy.GetFingerprint()] = true
		}
	}
	if !verifiedFingerprints[client.userPrivateKey.GetFingerprint()] {
		t.Errorf("missing verified signature from user key; verified: %v", verifiedFingerprints)
	}
	if !verifiedFingerprints[extraKey.GetFingerprint()] {
		t.Errorf("missing verified signature from extra signing key; verified: %v", verifiedFingerprints)
	}
	if len(verifiedFingerprints) != 2 {
		t.Errorf("expected exactly 2 verified signers, got %d: %v", len(verifiedFingerprints), verifiedFingerprints)
	}
}

// TestEncryptMessageWithKeyAndSigner_NilExtraSignerMatchesSingleSigner
// verifies that passing a nil extraSigningKey degrades cleanly to a single
// signature from the user's key, same as EncryptMessageWithKey. Callers
// (e.g. personal v5 metadata) rely on this to avoid a separate code path.
func TestEncryptMessageWithKeyAndSigner_NilExtraSignerMatchesSingleSigner(t *testing.T) {
	t.Parallel()

	client := newTestClientWithKey(t)
	recipient, err := crypto.NewKeyFromArmored(testPGPPublic(t))
	if err != nil {
		t.Fatalf("parse recipient key: %v", err)
	}
	decryptionKey, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("GetUserPrivateKeyCopy: %v", err)
	}

	armored, err := client.EncryptMessageWithKeyAndSigner(recipient, nil, "solo signed payload")
	if err != nil {
		t.Fatalf("EncryptMessageWithKeyAndSigner: %v", err)
	}

	res, err := crypto.PGP().Decryption().
		DecryptionKey(decryptionKey).
		VerificationKey(recipient).
		New()
	if err != nil {
		t.Fatalf("new decryptor: %v", err)
	}
	decrypted, err := res.Decrypt([]byte(armored), crypto.Armor)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(decrypted.Signatures) != 1 {
		t.Errorf("expected exactly 1 signature with nil extra signer, got %d", len(decrypted.Signatures))
	}
}

// TestEncryptMessageWithKeyAndSigner_FailsWithoutPrivateKey mirrors
// TestEncryptMessage_FailsWithoutPrivateKey: callers branch on the typed
// ErrNoPrivateKey, so a logged-out Client must not silently degrade to a
// generic error.
func TestEncryptMessageWithKeyAndSigner_FailsWithoutPrivateKey(t *testing.T) {
	t.Parallel()

	client := newTestClient(t)
	_, err := client.EncryptMessageWithKeyAndSigner(nil, nil, "message")
	if !errors.Is(err, ErrNoPrivateKey) {
		t.Errorf("got %v, want ErrNoPrivateKey", err)
	}
}

// The deprecated EncryptMessageWithPublicKey wrapper accepts an armored
// string instead of *crypto.Key. We verify it still works (kept for
// backward compat) by round-tripping through it.
func TestEncryptMessageWithPublicKey_DeprecatedWrapper(t *testing.T) {
	t.Parallel()

	client := newTestClientWithKey(t)
	armored, err := client.EncryptMessageWithPublicKey(testPGPPublic(t), "via deprecated wrapper")
	if err != nil {
		t.Fatalf("EncryptMessageWithPublicKey: %v", err)
	}
	got, err := client.DecryptMessage(armored)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if got != "via deprecated wrapper" {
		t.Errorf("got %q", got)
	}
}

// And its error path: a non-armored input must produce an error rather
// than encrypting against a nil/zero key.
func TestEncryptMessageWithPublicKey_InvalidPublicKey(t *testing.T) {
	t.Parallel()

	client := newTestClientWithKey(t)
	_, err := client.EncryptMessageWithPublicKey("not a key", "x")
	if err == nil {
		t.Fatal("expected error for invalid public key, got nil")
	}
}

// TestGetUserPrivateKeyCopy_ReturnsIndependentCopy enforces the
// thread-safety contract documented on GetUserPrivateKeyCopy: each call
// must return a fresh *crypto.Key whose lifecycle is independent of the
// cached one. gopenpgp's ClearPrivateParams() mutates the key in place;
// if Copy() were a no-op, calling it on a returned key would zero the
// client's cached key and break the next decryption.
func TestGetUserPrivateKeyCopy_ReturnsIndependentCopy(t *testing.T) {
	t.Parallel()

	client := newTestClientWithKey(t)
	copy1, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("GetUserPrivateKeyCopy: %v", err)
	}
	copy2, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("GetUserPrivateKeyCopy (2nd): %v", err)
	}
	if copy1 == copy2 {
		t.Error("two copies returned the same pointer; key sharing breaks isolation")
	}
	// Zero copy1 — the client's cached key and copy2 must remain usable.
	copy1.ClearPrivateParams()
	if _, err := client.GetUserPrivateKeyCopy(); err != nil {
		t.Errorf("clearing one copy poisoned the client's cached key: %v", err)
	}
}

func TestGetUserPrivateKeyCopy_WithoutKey(t *testing.T) {
	t.Parallel()

	client := newTestClient(t)
	_, err := client.GetUserPrivateKeyCopy()
	if !errors.Is(err, ErrNoPrivateKey) {
		t.Errorf("err = %v, want ErrNoPrivateKey", err)
	}
}

// TestEncryptDecrypt_ConcurrentSafety is the regression test for the
// cryptoMu race that previously caused intermittent decryption failures.
// gopenpgp's Key.Copy() is NOT safe under concurrent reads of the same
// key; the SDK uses cryptoMu to serialize access. Running 20 goroutines
// concurrently encrypting and decrypting forces any missed lock to
// surface as a -race detector report.
func TestEncryptDecrypt_ConcurrentSafety(t *testing.T) {
	t.Parallel()

	client := newTestClientWithKey(t)
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			armored, err := client.EncryptMessage("payload")
			if err != nil {
				errs <- err
				return
			}
			got, err := client.DecryptMessage(armored)
			if err != nil {
				errs <- err
				return
			}
			if got != "payload" {
				errs <- errors.New("decrypted mismatch")
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent op: %v", err)
	}
}

// TestGetPrivateKeyFromArmor_UnlockedKey covers the "key is not
// passphrase-protected" branch — the SDK must accept these without
// requiring a passphrase rather than rejecting them as malformed.
func TestGetPrivateKeyFromArmor_UnlockedKey(t *testing.T) {
	t.Parallel()

	key, err := crypto.PGP().KeyGeneration().AddUserId("u", "u@example.com").New().GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	armored, err := key.Armor()
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	got, err := GetPrivateKeyFromArmor(armored, nil)
	if err != nil {
		t.Fatalf("GetPrivateKeyFromArmor: %v", err)
	}
	if got == nil {
		t.Fatal("got nil key")
	}
}

// Locked-key branch: with the correct passphrase, we get back a usable
// key. This is the path Login() takes.
func TestGetPrivateKeyFromArmor_LockedKey(t *testing.T) {
	t.Parallel()

	armored, pass := testPGPKey(t)
	got, err := GetPrivateKeyFromArmor(armored, []byte(pass))
	if err != nil {
		t.Fatalf("GetPrivateKeyFromArmor: %v", err)
	}
	if got == nil {
		t.Fatal("got nil key")
	}
}

// Wrong passphrase must surface as an error rather than returning a
// partially-unlocked key (which would crash later during decryption).
func TestGetPrivateKeyFromArmor_WrongPassphrase(t *testing.T) {
	t.Parallel()

	armored, _ := testPGPKey(t)
	_, err := GetPrivateKeyFromArmor(armored, []byte("wrong"))
	if err == nil {
		t.Fatal("expected error for wrong passphrase, got nil")
	}
}

// Garbage input — proves the parser doesn't crash on non-PGP data.
func TestGetPrivateKeyFromArmor_Garbage(t *testing.T) {
	t.Parallel()

	_, err := GetPrivateKeyFromArmor("not a key", nil)
	if err == nil {
		t.Fatal("expected error for garbage input, got nil")
	}
}

// TestDecryptSecretWithResourceID_DelegatesToDecryptMessage proves the
// resource-aware wrapper is a thin shim: the resourceID is accepted for
// API compatibility but does NOT affect decryption (per-user secrets
// don't benefit from session-key caching, so the wrapper just calls
// DecryptMessage).
func TestDecryptSecretWithResourceID_DelegatesToDecryptMessage(t *testing.T) {
	t.Parallel()

	client := newTestClientWithKey(t)
	armored, err := client.EncryptMessage("secret-payload")
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	got, err := client.DecryptSecretWithResourceID(validUUID, armored)
	if err != nil {
		t.Fatalf("DecryptSecretWithResourceID: %v", err)
	}
	if got != "secret-payload" {
		t.Errorf("got %q, want %q", got, "secret-payload")
	}
}

// TestDecryptMessageWithPrivateKeyAndReturnSessionKey verifies the
// session-key extraction path used by metadata caching. The returned
// SessionKey, once cached, lets subsequent decryptions skip the
// expensive asymmetric step. A nil SessionKey return would silently
// disable the cache.
func TestDecryptMessageWithPrivateKeyAndReturnSessionKey_ReturnsBothPlaintextAndKey(t *testing.T) {
	t.Parallel()

	client := newTestClientWithKey(t)
	armored, err := client.EncryptMessage("hello")
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	keyCopy, err := client.GetUserPrivateKeyCopy()
	if err != nil {
		t.Fatalf("GetUserPrivateKeyCopy: %v", err)
	}

	plaintext, sessionKey, err := client.DecryptMessageWithPrivateKeyAndReturnSessionKey(keyCopy, armored)
	if err != nil {
		t.Fatalf("DecryptMessageWithPrivateKeyAndReturnSessionKey: %v", err)
	}
	if plaintext != "hello" {
		t.Errorf("plaintext = %q, want hello", plaintext)
	}
	if sessionKey == nil {
		t.Error("expected non-nil session key — caching depends on this return")
	}
}
