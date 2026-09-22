package tracer

import (
	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/plaintext"
)

// FetcherConfig is shared tracer configuration for flow and packet capture modes.
type FetcherConfig struct {
	config.Agent
	EnableIngress  bool
	EnableEgress   bool
	Debug          bool
	FilterConfig   []*FilterConfig
	PlaintextScope *plaintext.Scope
}
