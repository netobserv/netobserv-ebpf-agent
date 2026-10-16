package config

import (
	"github.com/caarlos0/env/v11"
	configflows "github.com/netobserv/netobserv-ebpf-agent/pkg/config/flows"
	configpackets "github.com/netobserv/netobserv-ebpf-agent/pkg/config/packets"
)

// Agent is the full agent configuration loaded from environment variables.
type Agent struct {
	Common
	Flows   configflows.Features
	Packets configpackets.Features
}

func FromEnv() (*Agent, error) {
	cfg := Agent{}
	if err := env.Parse(&cfg); err != nil {
		return nil, err
	}

	// Deprecated fields
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

	// Special defaults
	if cfg.CacheMaxDNSFlows == 0 {
		cfg.CacheMaxDNSFlows = cfg.CacheMaxFlows / 10
	}
	if cfg.CacheMaxNetworkEventFlows == 0 {
		cfg.CacheMaxNetworkEventFlows = cfg.CacheMaxFlows / 2
	}
	if cfg.CacheMaxPktDropsFlows == 0 {
		cfg.CacheMaxPktDropsFlows = cfg.CacheMaxFlows / 2
	}
	if cfg.CacheMaxXlatFlows == 0 {
		cfg.CacheMaxXlatFlows = cfg.CacheMaxFlows / 2
	}
	if cfg.CacheMaxAdditionalFlows == 0 {
		cfg.CacheMaxAdditionalFlows = cfg.CacheMaxFlows
	}

	return &cfg, nil
}
