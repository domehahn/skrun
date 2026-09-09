package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const SchemaVersion = "1.0.0"

type DeniedAction struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}
type WorkloadIdentity struct {
	HostID           string `json:"host_id,omitempty"`
	BinaryVersion    string `json:"binary_version,omitempty"`
	Platform         string `json:"platform,omitempty"`
	IsolationBackend string `json:"isolation_backend,omitempty"`
}

type ResourceUsage struct {
	StdoutBytes int64 `json:"stdout_bytes"`
	StderrBytes int64 `json:"stderr_bytes"`
	DurationMS  int64 `json:"duration_ms"`
}

type Receipt struct {
	SchemaVersion      string            `json:"schema_version"`
	ExecutionID        string            `json:"execution_id"`
	ArtifactDigest     string            `json:"artifact_digest"`
	DecisionID         string            `json:"decision_id,omitempty"`
	PolicyDigest       string            `json:"policy_digest"`
	WorkloadIdentity   *WorkloadIdentity `json:"workload_identity,omitempty"`
	IsolationBackend   string            `json:"isolation_backend"`
	StartedAt          time.Time         `json:"started_at"`
	FinishedAt         time.Time         `json:"finished_at"`
	Result             string            `json:"result"`
	ExitCode           int               `json:"exit_code"`
	TimedOut           bool              `json:"timed_out"`
	OutputTruncated    bool              `json:"output_truncated"`
	Stdout             string            `json:"stdout,omitempty"`
	Stderr             string            `json:"stderr,omitempty"`
	StdoutDigest       string            `json:"stdout_digest,omitempty"`
	StderrDigest       string            `json:"stderr_digest,omitempty"`
	ResourceUsage      *ResourceUsage    `json:"resource_usage,omitempty"`
	DeniedActions      []DeniedAction    `json:"denied_actions"`
	Error              string            `json:"error,omitempty"`
	Signature          string            `json:"signature,omitempty"`
	SignatureAlgorithm string            `json:"signature_algorithm,omitempty"`
}

func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func (r Receipt) CanonicalBytes() ([]byte, error) {
	clone := r
	clone.Signature = ""
	clone.SignatureAlgorithm = ""
	return json.Marshal(clone)
}

func (r *Receipt) Sign(priv ed25519.PrivateKey) error {
	data, err := r.CanonicalBytes()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, data)
	r.SignatureAlgorithm = "ed25519"
	r.Signature = hex.EncodeToString(sig)
	return nil
}

func (r Receipt) Verify(pub ed25519.PublicKey) error {
	if r.Signature == "" {
		return errors.New("receipt is not signed")
	}
	if r.SignatureAlgorithm != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q", r.SignatureAlgorithm)
	}
	sigBytes, err := hex.DecodeString(r.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature hex string")
	}
	data, err := r.CanonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, data, sigBytes) {
		return errors.New("receipt signature verification failed")
	}
	return nil
}
