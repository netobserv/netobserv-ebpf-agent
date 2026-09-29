package config

import (
	"fmt"

	configflows "github.com/netobserv/netobserv-ebpf-agent/pkg/config/flows"
	configpackets "github.com/netobserv/netobserv-ebpf-agent/pkg/config/packets"
)

// ValidateForPackets rejects flow-only options when packet capture mode is selected.
func (a *Agent) ValidateForPackets() error {
	return configflows.Validate(&a.Flows)
}

// ValidateForFlows validates flow settings and rejects packet-capture-only options.
func (a *Agent) ValidateForFlows() error {
	if a.Flows.EndpointMapMaxEntries == 0 {
		return fmt.Errorf("ENDPOINT_MAP_MAX_ENTRIES must be greater than zero")
	}
	return configpackets.Validate(a.Packets)
}
