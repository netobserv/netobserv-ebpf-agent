package config

// Normalize applies the default values of the configuration settings that are
// left unset, and the deprecated settings mappings.
// cpus is the number of possible CPUs of the host: every entry of a per-CPU
// BPF map costs one value per possible CPU, so the default capacity of these
// maps is derived from CacheMaxFlows divided by that number, keeping their
// memory footprint roughly independent from the host CPU count.
func (a *Agent) Normalize(cpus int) {
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

	if a.CacheMaxFlows <= 0 {
		a.CacheMaxFlows = 5000 // Env default
	}

	// Special defaults
	if a.CacheMaxDNSFlows <= 0 {
		a.CacheMaxDNSFlows = max(a.CacheMaxFlows/10, 1)
	}
	if a.CacheMaxQUICFlows <= 0 {
		a.CacheMaxQUICFlows = max(a.CacheMaxFlows/2, 1)
	}
	// Per-CPU map defaults (network events, pkt drops, xlat, additional data).
	// The extra division by 2 is an empirical tuning: these maps are not
	// expected to track as many flows as the main flows map.
	cpus = max(cpus, 1)
	if a.CacheMaxNetworkEventFlows <= 0 {
		a.CacheMaxNetworkEventFlows = max(a.CacheMaxFlows/cpus, 1)
	}
	if a.CacheMaxPktDropsFlows <= 0 {
		a.CacheMaxPktDropsFlows = max(a.CacheMaxFlows/cpus, 1)
	}
	if a.CacheMaxXlatFlows <= 0 {
		a.CacheMaxXlatFlows = max(a.CacheMaxFlows/cpus, 1)
	}
	if a.CacheMaxAdditionalFlows <= 0 {
		a.CacheMaxAdditionalFlows = max(a.CacheMaxFlows/cpus, 1)
	}
}
