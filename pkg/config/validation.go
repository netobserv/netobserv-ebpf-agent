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

func (a *Agent) Normalize() {
	// Deprecated fields
	if len(a.FlowsTargetHost) != 0 {
		clog.Infof("Using deprecated FlowsTargetHost %s", a.FlowsTargetHost)
		a.TargetHost = a.FlowsTargetHost
	}

	if a.FlowsTargetPort != 0 {
		clog.Infof("Using deprecated FlowsTargetPort %d", a.FlowsTargetPort)
		a.TargetPort = a.FlowsTargetPort
	} else if a.PCAServerPort != 0 {
		clog.Infof("Using deprecated PCAServerPort %d", a.PCAServerPort)
		a.TargetPort = a.PCAServerPort
	}

	// Special defaults
	if a.CacheMaxDNSFlows <= 0 {
		a.CacheMaxDNSFlows = max(a.CacheMaxFlows/10, 1)
	}
	if a.CacheMaxNetworkEventFlows <= 0 {
		a.CacheMaxNetworkEventFlows = max(a.CacheMaxFlows/2, 1)
	}
	if a.CacheMaxPktDropsFlows <= 0 {
		a.CacheMaxPktDropsFlows = max(a.CacheMaxFlows/2, 1)
	}
	if a.CacheMaxXlatFlows <= 0 {
		a.CacheMaxXlatFlows = max(a.CacheMaxFlows/2, 1)
	}
	if a.CacheMaxAdditionalFlows <= 0 {
		a.CacheMaxAdditionalFlows = max(a.CacheMaxFlows, 1)
	}
}
