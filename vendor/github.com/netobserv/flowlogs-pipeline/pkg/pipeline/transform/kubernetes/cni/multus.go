package cni

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	v1 "k8s.io/api/core/v1"
)

const (
	statusAnnotation = "k8s.v1.cni.cncf.io/network-status"
	// Index names
	indexIP        = "ip"
	indexMAC       = "mac"
	indexInterface = "interface"
)

type MultusHandler struct {
}

func (m *MultusHandler) Manages(indexKey string) bool {
	return indexKey == indexIP || indexKey == indexMAC || indexKey == indexInterface
}

func (m *MultusHandler) BuildKeys(flow config.GenericMap, rule *api.K8sRule, secNets []api.SecondaryNetwork) []string {
	if len(secNets) == 0 {
		return nil
	}
	var keys []string
	for _, sn := range secNets {
		snKeys := m.buildSNKeys(flow, rule, &sn)
		if snKeys != nil {
			keys = append(keys, snKeys...)
		}
	}
	return keys
}

func (m *MultusHandler) buildSNKeys(flow config.GenericMap, rule *api.K8sRule, sn *api.SecondaryNetwork) []string {
	var keys []string

	var ip, mac string
	var interfaces []string
	if _, ok := sn.Index[indexIP]; ok && len(rule.IPField) > 0 {
		ip, ok = flow.LookupString(rule.IPField)
		if !ok {
			return nil
		}
	}
	if _, ok := sn.Index[indexMAC]; ok && len(rule.MACField) > 0 {
		mac, ok = flow.LookupString(rule.MACField)
		if !ok {
			return nil
		}
	}
	if _, ok := sn.Index[indexInterface]; ok && len(rule.InterfacesField) > 0 {
		v, ok := flow[rule.InterfacesField]
		if !ok {
			return nil
		}
		interfaces, ok = v.([]string)
		if !ok {
			return nil
		}
	}
	if mac == "" && ip == "" && len(interfaces) == 0 {
		return nil
	}

	macIP := "~" + ip + "~" + strings.ToLower(mac)
	if interfaces == nil {
		return []string{macIP}
	}
	for _, intf := range interfaces {
		keys = append(keys, intf+macIP)
	}

	return keys
}

// GetPodUniqueKeys returns both flat keys and named keys
func (m *MultusHandler) GetPodUniqueKeys(pod *v1.Pod, secNets []api.SecondaryNetwork) ([]string, map[string]string, error) {
	if len(secNets) == 0 {
		return nil, nil, nil
	}
	// Cf https://k8snetworkplumbingwg.github.io/multus-cni/docs/quickstart.html#network-status-annotations
	if statusAnnotationJSON, ok := pod.Annotations[statusAnnotation]; ok {
		var networks []NetStatItem
		if err := json.Unmarshal([]byte(statusAnnotationJSON), &networks); err != nil {
			return nil, nil, fmt.Errorf("failed to index from network-status annotation, cannot read annotation %s: %w", statusAnnotation, err)
		}
		namedKeys := make(map[string]string)
		var flatKeys []string
		for _, network := range networks {
			// Ignore default network, focus on secondary
			if !network.Default {
				for _, snConfig := range secNets {
					keys := network.Keys(snConfig.Index)
					flatKeys = append(flatKeys, keys...)
					for _, k := range keys {
						namedKeys[k] = network.Name
					}
				}
			}
		}
		return flatKeys, namedKeys, nil
	}
	// Annotation not present => just ignore, no error
	return nil, nil, nil
}

type NetStatItem struct {
	Name      string   `json:"name"`
	Default   bool     `json:"default"`
	Interface string   `json:"interface"`
	IPs       []string `json:"ips"`
	MAC       string   `json:"mac"`
}

func (n *NetStatItem) Keys(configuredIndex map[string]any) []string {
	var mac, intf string
	// Return nil when the network info misses any configured index
	if _, ok := configuredIndex[indexMAC]; ok {
		if len(n.MAC) == 0 {
			return nil
		}
		mac = n.MAC
	}
	if _, ok := configuredIndex[indexInterface]; ok {
		if len(n.Interface) == 0 {
			return nil
		}
		intf = n.Interface
	}
	if _, ok := configuredIndex[indexIP]; ok {
		if len(n.IPs) == 0 {
			return nil
		}
		var keys []string
		for _, ip := range n.IPs {
			keys = append(keys, key(intf, ip, mac))
		}
		return keys
	}
	// Ignore IP
	return []string{key(intf, "", mac)}
}

func key(intf, ip, mac string) string {
	return intf + "~" + ip + "~" + strings.ToLower(mac)
}
