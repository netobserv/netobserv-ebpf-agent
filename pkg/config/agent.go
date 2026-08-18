package config

import (
	configflows "github.com/netobserv/netobserv-ebpf-agent/pkg/config/flows"
	configpackets "github.com/netobserv/netobserv-ebpf-agent/pkg/config/packets"
)

// Agent is the full agent configuration loaded from environment variables.
type Agent struct {
	Common
	Flows   configflows.Features
	Packets configpackets.Features
}

// ManageDeprecatedConfigs migrates deprecated environment variable names.
func ManageDeprecatedConfigs(cfg *Agent) {
	if len(cfg.FlowsTargetHost) != 0 {
		clog.Infof("Using deprecated FlowsTargetHost %s", cfg.FlowsTargetHost)
		cfg.TargetHost = cfg.FlowsTargetHost
	}

	if cfg.FlowsTargetPort != 0 {
		clog.Infof("Using deprecated FlowsTargetPort %d", cfg.FlowsTargetPort)
		cfg.TargetPort = cfg.FlowsTargetPort
	} else if cfg.PCAServerPort != 0 {
		clog.Infof("Using deprecated PCAServerPort %d", cfg.PCAServerPort)
		cfg.TargetPort = cfg.PCAServerPort
	}
}
