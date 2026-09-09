package broker

import (
	"testing"

	"github.com/domehahn/skrun/internal/policy"
)

func TestEgressBroker(t *testing.T) {
	p := policy.Policy{
		AllowNetwork: true,
		AllowedEgress: []policy.EgressRule{
			{Domain: "*.api.github.com", Port: 443},
			{Domain: "openai.com", Port: 443},
			{Domain: "*.anthropic.com"},
		},
	}
	eb := NewEgressBroker(p)

	tests := []struct {
		domain string
		port   int
		allow  bool
	}{
		{"v3.api.github.com", 443, true},
		{"api.github.com", 443, true},
		{"github.com", 443, false},
		{"openai.com", 443, true},
		{"openai.com", 80, false},
		{"api.anthropic.com", 8080, true},
		{"malicious.com", 443, false},
	}

	for _, tt := range tests {
		ok, reason := eb.AuthorizeEgress(tt.domain, tt.port)
		if ok != tt.allow {
			t.Errorf("AuthorizeEgress(%q, %d) = %v (%s), want %v", tt.domain, tt.port, ok, reason, tt.allow)
		}
	}
}

func TestEgressBrokerDisabledNetwork(t *testing.T) {
	p := policy.Policy{
		AllowNetwork: false,
		AllowedEgress: []policy.EgressRule{
			{Domain: "*"},
		},
	}
	eb := NewEgressBroker(p)
	if ok, _ := eb.AuthorizeEgress("example.com", 80); ok {
		t.Fatal("expected egress denial when network is disabled")
	}
}

func TestSSRFBlocking(t *testing.T) {
	p := policy.Policy{
		AllowNetwork: true,
		AllowedEgress: []policy.EgressRule{
			{Domain: "*"},
		},
	}
	eb := NewEgressBroker(p)

	ssrfTargets := []string{
		"169.254.169.254",
		"127.0.0.1",
		"localhost",
		"10.0.0.1",
		"192.168.1.1",
	}

	for _, target := range ssrfTargets {
		if ok, reason := eb.AuthorizeEgress(target, 80); ok {
			t.Errorf("expected SSRF target %s to be blocked even with wildcard egress rule, got allowed (%s)", target, reason)
		}
	}
}

func TestMCPBroker(t *testing.T) {
	p := policy.Policy{
		MCPBroker: &policy.MCPBrokerConfig{
			AllowedTools: []string{
				"filesystem/*",
				"search/query",
			},
		},
	}
	mb := NewMCPBroker(p)

	tests := []struct {
		tool  string
		allow bool
	}{
		{"filesystem/read_file", true},
		{"filesystem/write_file", true},
		{"search/query", true},
		{"search/delete", false},
		{"exec/command", false},
	}

	for _, tt := range tests {
		ok, reason := mb.AuthorizeTool(tt.tool)
		if ok != tt.allow {
			t.Errorf("AuthorizeTool(%q) = %v (%s), want %v", tt.tool, ok, reason, tt.allow)
		}
	}
}
