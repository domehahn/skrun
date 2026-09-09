package broker

import (
	"fmt"
	"path"
	"strings"

	"github.com/domehahn/skrun/internal/policy"
)

type EgressBroker struct {
	AllowNetwork  bool
	AllowedEgress []policy.EgressRule
}

func NewEgressBroker(p policy.Policy) *EgressBroker {
	return &EgressBroker{
		AllowNetwork:  p.AllowNetwork,
		AllowedEgress: p.AllowedEgress,
	}
}

func (e *EgressBroker) AuthorizeEgress(domain string, port int) (bool, string) {
	if !e.AllowNetwork {
		return false, "network access is disabled by policy"
	}
	if len(e.AllowedEgress) == 0 {
		// If network is allowed and no egress rules are specified, all egress is allowed.
		return true, "unrestricted network access allowed"
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, rule := range e.AllowedEgress {
		rDomain := strings.ToLower(strings.TrimSpace(rule.Domain))
		if rule.Port != 0 && rule.Port != port {
			continue
		}
		if matchDomain(rDomain, domain) {
			return true, fmt.Sprintf("matched allowed egress rule %s", rule.Domain)
		}
	}
	return false, fmt.Sprintf("egress to %s:%d denied by policy egress filter", domain, port)
}

func matchDomain(pattern, domain string) bool {
	if pattern == "*" || pattern == domain {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g. ".github.com"
		return strings.HasSuffix(domain, suffix) || domain == pattern[2:]
	}
	return false
}

type MCPBroker struct {
	Config *policy.MCPBrokerConfig
}

func NewMCPBroker(p policy.Policy) *MCPBroker {
	return &MCPBroker{
		Config: p.MCPBroker,
	}
}

func (m *MCPBroker) AuthorizeTool(toolName string) (bool, string) {
	if m.Config == nil || len(m.Config.AllowedTools) == 0 {
		return false, "no MCP tools authorized by policy"
	}
	toolName = strings.TrimSpace(toolName)
	for _, pattern := range m.Config.AllowedTools {
		pattern = strings.TrimSpace(pattern)
		if pattern == "*" || pattern == toolName {
			return true, fmt.Sprintf("matched allowed MCP tool rule %q", pattern)
		}
		matched, err := path.Match(pattern, toolName)
		if err == nil && matched {
			return true, fmt.Sprintf("matched allowed MCP tool rule %q", pattern)
		}
	}
	return false, fmt.Sprintf("MCP tool %q denied by policy broker", toolName)
}
