package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

const SchemaVersion = "1.0.0"

var secretName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

type ResourceLimits struct {
	MaxMemoryMB int `json:"max_memory_mb,omitempty"`
	MaxCPUs     int `json:"max_cpus,omitempty"`
	MaxPIDs     int `json:"max_pids,omitempty"`
	MaxFDs      int `json:"max_fds,omitempty"`
}

type EgressRule struct {
	Domain string `json:"domain"`
	Port   int    `json:"port,omitempty"`
}

type MCPBrokerConfig struct {
	AllowedTools []string `json:"allowed_tools,omitempty"`
	ServerURI    string   `json:"server_uri,omitempty"`
}

type Policy struct {
	SchemaVersion       string           `json:"schema_version"`
	ArtifactDigest      string           `json:"artifact_digest"`
	AllowedCommands     []string         `json:"allowed_commands"`
	AllowedSecrets      []string         `json:"allowed_secrets"`
	AllowWorkspaceWrite bool             `json:"allow_workspace_write"`
	AllowNetwork        bool             `json:"allow_network"`
	AllowedEgress       []EgressRule     `json:"allowed_egress,omitempty"`
	ResourceLimits      *ResourceLimits  `json:"resource_limits,omitempty"`
	MCPBroker           *MCPBrokerConfig `json:"mcp_broker,omitempty"`
	PublicKey           string           `json:"public_key,omitempty"`
	TimeoutSeconds      int              `json:"timeout_seconds"`
	MaxOutputBytes      int64            `json:"max_output_bytes"`
}

type decisionEnvelope struct {
	RuntimePolicy *Policy `json:"runtime_policy"`
}

func Load(path string) (Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	return Parse(b)
}
func Parse(b []byte) (Policy, error) {
	var env decisionEnvelope
	if err := json.Unmarshal(b, &env); err == nil && env.RuntimePolicy != nil {
		if err := env.RuntimePolicy.Validate(); err != nil {
			return Policy{}, err
		}
		return *env.RuntimePolicy, nil
	}
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("parse runtime policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}
func (p Policy) Validate() error {
	if p.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", p.SchemaVersion)
	}
	if !strings.HasPrefix(p.ArtifactDigest, "sha256:") || len(p.ArtifactDigest) != 71 {
		return fmt.Errorf("artifact_digest must be sha256:<64 hex>")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(p.ArtifactDigest, "sha256:")); err != nil {
		return fmt.Errorf("artifact_digest: %w", err)
	}
	if p.TimeoutSeconds <= 0 || p.TimeoutSeconds > 86400 {
		return fmt.Errorf("timeout_seconds must be between 1 and 86400")
	}
	if p.MaxOutputBytes <= 0 || p.MaxOutputBytes > 1<<30 {
		return fmt.Errorf("max_output_bytes must be between 1 and 1073741824")
	}
	for _, c := range p.AllowedCommands {
		if strings.TrimSpace(c) == "" || strings.ContainsAny(c, "/\\") {
			return fmt.Errorf("allowed command must be a basename, got %q", c)
		}
	}
	for _, s := range p.AllowedSecrets {
		if !secretName.MatchString(s) {
			return fmt.Errorf("invalid secret environment name %q", s)
		}
	}
	if p.ResourceLimits != nil {
		if p.ResourceLimits.MaxMemoryMB < 0 || p.ResourceLimits.MaxCPUs < 0 || p.ResourceLimits.MaxPIDs < 0 || p.ResourceLimits.MaxFDs < 0 {
			return fmt.Errorf("resource limits values must be non-negative")
		}
	}
	for _, e := range p.AllowedEgress {
		if strings.TrimSpace(e.Domain) == "" {
			return fmt.Errorf("allowed egress domain cannot be empty")
		}
		if e.Port < 0 || e.Port > 65535 {
			return fmt.Errorf("invalid egress port %d", e.Port)
		}
	}
	if p.MCPBroker != nil {
		for _, tool := range p.MCPBroker.AllowedTools {
			if strings.TrimSpace(tool) == "" {
				return fmt.Errorf("allowed MCP tool cannot be empty")
			}
		}
	}
	if p.PublicKey != "" {
		if len(p.PublicKey) != 64 {
			return fmt.Errorf("public_key must be 64 hex characters Ed25519 public key")
		}
		if _, err := hex.DecodeString(p.PublicKey); err != nil {
			return fmt.Errorf("invalid public_key hex: %w", err)
		}
	}
	return nil
}
func (p Policy) AllowsCommand(name string) bool { return slices.Contains(p.AllowedCommands, name) }
func (p Policy) Digest() string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
