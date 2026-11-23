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

// FromEnv loads the agent configuration from the environment variables.
// cpus is the number of possible CPUs of the host, used to derive the default
// capacity of the per-CPU BPF maps (see Normalize).
func FromEnv(cpus int) (*Agent, error) {
	cfg := Agent{}
	if err := env.Parse(&cfg); err != nil {
		return nil, err
	}
	cfg.Normalize(cpus)
	return &cfg, nil
}
