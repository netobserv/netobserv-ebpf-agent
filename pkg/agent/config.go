package agent

import (
	"net"
	"time"
)

// TODO: NETOBSERV-201: fill from CLI and env
type Config struct {
	// Ifaces contains the interface names where flow traces will be attached. If empty, the agent
	// will fetch all the interfaces in the system, excepting the ones listed in ExcludeIfaces
	Ifaces []string
	// ExcludeIfaces contains the interface names that will be excluded from flow tracing. Default:
	// "lo" (loopback)
	ExcludeIfaces []string
	// BuffersLen establishes the length of communication channels between the different processing
	// stages
	BuffersLen int
	// CacheMaxFlows specifies how many flows can be accumulated in the accounting cache before
	// being flushing the cache for its later export
	CacheMaxFlows int
	// CacheActiveTimeout specifies the maximum duration in which a flow is kept in the accounting
	// cache before being flushed for its later export
	CacheActiveTimeout time.Duration
	// Verbose mode
	Verbose bool
}

func getInterfaces(cfg *Config) (map[string]struct{}, error) {
	// get interfaces from configuration or acquire them from the system
	ifaces := map[string]struct{}{}
	if cfg.Ifaces != nil {
		for _, iface := range cfg.Ifaces {
			ifaces[iface] = struct{}{}
		}
		return ifaces, nil
	}
	nifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range nifaces {
		ifaces[iface.Name] = struct{}{}
	}
	// exclude interfaces
	for _, iface := range cfg.ExcludeIfaces {
		delete(ifaces, iface)
	}
	return ifaces, nil
}
