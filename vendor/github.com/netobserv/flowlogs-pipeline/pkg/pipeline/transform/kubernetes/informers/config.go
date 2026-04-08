package informers

import (
	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/transform/kubernetes/cni"
)

var (
	cniPlugins = map[string]cni.Plugin{
		api.OVN: &cni.OVNPlugin{},
	}
	multus = cni.MultusHandler{}
	udn    = cni.UDNHandler{}
)

type Config struct {
	managedCNI        []string
	secondaryNetworks []api.SecondaryNetwork
	hasMultus         bool
	hasUDN            bool
	trackedKinds      []string
}

func NewConfig(cfg *api.NetworkTransformKubeConfig) Config {
	c := Config{
		managedCNI:        cfg.ManagedCNI,
		secondaryNetworks: cfg.SecondaryNetworks,
		trackedKinds:      cfg.TrackedKinds,
	}
	if c.managedCNI == nil {
		c.managedCNI = []string{api.OVN}
	}
	for _, netConfig := range cfg.SecondaryNetworks {
		for index := range netConfig.Index {
			if multus.Manages(index) {
				c.hasMultus = true
			}
			if udn.Manages(index) {
				c.hasUDN = true
			}
		}
	}
	return c
}

func (k *Config) BuildSecondaryNetworkKeys(flow config.GenericMap, rule *api.K8sRule) []string {
	var keys []string
	if k.hasMultus {
		keys = append(keys, multus.BuildKeys(flow, rule, k.secondaryNetworks)...)
	}
	if k.hasUDN {
		keys = append(keys, udn.BuildKeys(flow, rule)...)
	}
	return keys
}
