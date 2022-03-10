package agent

import (
	"net"
	"time"
)

// TODO: NETOBSERV-201: fill from CLI and env
type Config struct {
	Ifaces             []string
	ExcludeIfaces      []string
	BuffersLen         int
	AccountMaxEntries  int
	AccountEvictPeriod time.Duration
	Verbose            bool
}

func getInterfaces(cfg *Config) (map[string]struct{}, error) {
	// get interfaces from configuration or acquire them from the system
	ifaces := map[string]struct{}{}
	if cfg.Ifaces != nil {
		for _, iface := range cfg.Ifaces {
			ifaces[iface] = struct{}{}
		}
	} else {
		nifaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		for _, iface := range nifaces {
			ifaces[iface.Name] = struct{}{}
		}
	}
	// exclude interfaces
	for _, iface := range cfg.ExcludeIfaces {
		delete(ifaces, iface)
	}
	return ifaces, nil
}
