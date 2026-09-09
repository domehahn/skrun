package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

func TestReceiptSigningAndVerification(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	rc := Receipt{
		SchemaVersion:    SchemaVersion,
		ExecutionID:      "exec-12345",
		ArtifactDigest:   "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PolicyDigest:     "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		IsolationBackend: "linux-bubblewrap",
		StartedAt:        time.Now().UTC(),
		FinishedAt:       time.Now().UTC(),
		Result:           "SUCCESS",
		ExitCode:         0,
	}

	if err := rc.Verify(pub); err == nil {
		t.Fatal("expected error when verifying unsigned receipt")
	}

	if err := rc.Sign(priv); err != nil {
		t.Fatalf("failed to sign receipt: %v", err)
	}

	if rc.Signature == "" || rc.SignatureAlgorithm != "ed25519" {
		t.Fatalf("expected signature to be set, got signature=%q algo=%q", rc.Signature, rc.SignatureAlgorithm)
	}

	if err := rc.Verify(pub); err != nil {
		t.Fatalf("failed to verify signed receipt: %v", err)
	}

	// Tamper with receipt
	tampered := rc
	tampered.Result = "FAILED"
	if err := tampered.Verify(pub); err == nil {
		t.Fatal("expected verification failure for tampered receipt")
	}

	// Wrong public key
	pub2, _, _ := ed25519.GenerateKey(nil)
	if err := rc.Verify(pub2); err == nil {
		t.Fatal("expected verification failure with wrong public key")
	}
}

func TestReceiptPublicKeyHexParsing(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	pubHex := hex.EncodeToString(pub)

	rc := Receipt{
		SchemaVersion:  SchemaVersion,
		ExecutionID:    "exec-54321",
		ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Result:         "SUCCESS",
	}
	_ = rc.Sign(priv)

	decodedPub, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatalf("failed to decode pubkey hex: %v", err)
	}

	if err := rc.Verify(ed25519.PublicKey(decodedPub)); err != nil {
		t.Fatalf("verification failed with decoded public key: %v", err)
	}
}
