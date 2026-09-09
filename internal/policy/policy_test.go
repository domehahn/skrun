package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestParseDecisionEnvelope(t *testing.T) {
	p := Policy{SchemaVersion: "1.0.0", ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AllowedCommands: []string{"echo"}, TimeoutSeconds: 1, MaxOutputBytes: 10}
	b, _ := json.Marshal(map[string]any{"runtime_policy": p})
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.ArtifactDigest != p.ArtifactDigest {
		t.Fatal("wrong digest")
	}
}
func TestRejectSecretName(t *testing.T) {
	p := Policy{SchemaVersion: "1.0.0", ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AllowedSecrets: []string{"bad-name"}, TimeoutSeconds: 1, MaxOutputBytes: 10}
	if p.Validate() == nil {
		t.Fatal("expected error")
	}
}

func TestValidateResourceLimitsAndBroker(t *testing.T) {
	p := Policy{
		SchemaVersion:   "1.0.0",
		ArtifactDigest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AllowedCommands: []string{"echo"},
		TimeoutSeconds:  10,
		MaxOutputBytes:  1024,
		ResourceLimits:  &ResourceLimits{MaxMemoryMB: 512, MaxPIDs: 100},
		AllowedEgress:   []EgressRule{{Domain: "api.github.com", Port: 443}},
		MCPBroker:       &MCPBrokerConfig{AllowedTools: []string{"filesystem/read"}},
		PublicKey:       "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	badKey := p
	badKey.PublicKey = "invalid-key"
	if err := badKey.Validate(); err == nil {
		t.Fatal("expected error for invalid public key")
	}

	badLimits := p
	badLimits.ResourceLimits = &ResourceLimits{MaxMemoryMB: -10}
	if err := badLimits.Validate(); err == nil {
		t.Fatal("expected error for negative resource limit")
	}

	badEgress := p
	badEgress.AllowedEgress = []EgressRule{{Domain: ""}}
	if err := badEgress.Validate(); err == nil {
		t.Fatal("expected error for empty egress domain")
	}
}

func TestSignedDecisionEnvelope(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	p := Policy{
		SchemaVersion:   "1.0.0",
		ArtifactDigest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AllowedCommands: []string{"echo"},
		TimeoutSeconds:  5,
		MaxOutputBytes:  1024,
	}

	env := DecisionEnvelope{
		DecisionID:    "dec-999",
		Decision:      "ALLOW",
		Environment:   "production",
		RuntimePolicy: &p,
		IssuedBy:      "skgate-prod",
	}

	data, err := env.CanonicalBytes()
	if err != nil {
		t.Fatalf("failed canonical bytes: %v", err)
	}

	sig := ed25519.Sign(priv, data)
	env.Signature = hex.EncodeToString(sig)

	if err := env.Verify(pub); err != nil {
		t.Fatalf("failed to verify valid decision envelope: %v", err)
	}

	// Tamper with envelope
	tampered := env
	tampered.Decision = "DENY"
	if err := tampered.Verify(pub); err == nil {
		t.Fatal("expected error for tampered decision envelope")
	}
}
