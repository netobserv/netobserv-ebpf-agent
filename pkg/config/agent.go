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
	cfg.Normalize()
	return &cfg, nil
}
