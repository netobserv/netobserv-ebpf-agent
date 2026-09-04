package config

import (
	configflows "github.com/netobserv/netobserv-ebpf-agent/pkg/config/flows"
	configpackets "github.com/netobserv/netobserv-ebpf-agent/pkg/config/packets"
)

// ValidateForPackets rejects flow-only options when packet capture mode is selected.
func (a *Agent) ValidateForPackets() error {
	return configflows.Validate(&a.Flows)
}

// ValidateForFlows rejects packet-capture-only options in flow mode.
func (a *Agent) ValidateForFlows() error {
	return configpackets.Validate(a.Packets)
}
