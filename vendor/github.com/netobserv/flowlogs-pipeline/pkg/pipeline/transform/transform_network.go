/*
 * Copyright (C) 2021 IBM, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package transform

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/operational"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/transform/kubernetes"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/transform/location"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/transform/netdb"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/utils"
	util "github.com/netobserv/flowlogs-pipeline/pkg/utils"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("component", "transform.Network")

type Network struct {
	api.TransformNetwork
	svcNames     *netdb.ServiceNames
	snLabels     []subnetLabel
	ipLabelCache *utils.TimedCache
	m            sync.RWMutex
}

type subnetLabel struct {
	cidrs []*net.IPNet
	name  string
}

//nolint:cyclop
func (n *Network) Transform(inputEntry config.GenericMap) (config.GenericMap, bool) {
	// copy input entry before transform to avoid alteration on parallel stages
	outputEntry := inputEntry.Copy()

	n.m.RLock()
	defer n.m.RUnlock()

	for _, rule := range n.Rules {
		switch rule.Type {
		case api.NetworkAddSubnet:
			if rule.AddSubnet == nil {
				log.Errorf("Missing add subnet configuration")
				continue
			}
			if v, ok := outputEntry.LookupString(rule.AddSubnet.Input); ok {
				_, ipv4Net, err := net.ParseCIDR(v + rule.AddSubnet.SubnetMask)
				if err != nil {
					log.Warningf("Can't find subnet for IP %v and prefix length %s - err %v", v, rule.AddSubnet.SubnetMask, err)
					continue
				}
				outputEntry[rule.AddSubnet.Output] = ipv4Net.String()
			}
		case api.NetworkAddLocation:
			var locationInfo *location.Info
			locationInfo, err := location.GetLocation(util.ConvertToString(outputEntry[rule.AddLocation.Input]))
			if err != nil {
				log.Warningf("Can't find location for IP %v err %v", outputEntry[rule.AddLocation.Input], err)
				continue
			}
			outputEntry[rule.AddLocation.Output+"_CountryName"] = locationInfo.CountryName
			outputEntry[rule.AddLocation.Output+"_CountryLongName"] = locationInfo.CountryLongName
			outputEntry[rule.AddLocation.Output+"_RegionName"] = locationInfo.RegionName
			outputEntry[rule.AddLocation.Output+"_CityName"] = locationInfo.CityName
			outputEntry[rule.AddLocation.Output+"_Latitude"] = locationInfo.Latitude
			outputEntry[rule.AddLocation.Output+"_Longitude"] = locationInfo.Longitude
		case api.NetworkAddService:
			if rule.AddService == nil {
				log.Errorf("Missing add service configuration")
				continue
			}
			// Should be optimized (unused in netobserv)
			protocol := fmt.Sprintf("%v", outputEntry[rule.AddService.Protocol])
			portNumber, err := strconv.Atoi(fmt.Sprintf("%v", outputEntry[rule.AddService.Input]))
			if err != nil {
				log.Errorf("Can't convert port to int: Port %v - err %v", outputEntry[rule.AddService.Input], err)
				continue
			}
			var serviceName string
			protocolAsNumber, err := strconv.Atoi(protocol)
			if err == nil {
				// protocol has been submitted as number
				serviceName = n.svcNames.ByPortAndProtocolNumber(portNumber, protocolAsNumber)
			} else {
				// protocol has been submitted as any string
				serviceName = n.svcNames.ByPortAndProtocolName(portNumber, protocol)
			}
			if serviceName == "" {
				if err != nil {
					log.Debugf("Can't find service name for Port %v and protocol %v - err %v", outputEntry[rule.AddService.Input], protocol, err)
					continue
				}
			}
			outputEntry[rule.AddService.Output] = serviceName
		case api.NetworkAddKubernetes:
			kubernetes.Enrich(outputEntry, rule.Kubernetes)
		case api.NetworkAddKubernetesInfra:
			if rule.KubernetesInfra == nil {
				logrus.Error("transformation rule: Missing configuration ")
				continue
			}
			kubernetes.EnrichLayer(outputEntry, rule.KubernetesInfra)
		case api.NetworkReinterpretDirection:
			reinterpretDirection(outputEntry, &n.DirectionInfo)
		case api.NetworkAddSubnetLabel:
			if rule.AddSubnetLabel == nil {
				logrus.Error("AddSubnetLabel rule: Missing configuration ")
				continue
			}
			if anyIP, ok := outputEntry[rule.AddSubnetLabel.Input]; ok {
				if strIP, ok := anyIP.(string); ok {
					keys := []string{strIP}
					lbl, ok := n.ipLabelCache.GetCacheEntry(keys)
					if !ok {
						lbl = n.applySubnetLabel(strIP)
						n.ipLabelCache.UpdateCacheEntry(keys, func() interface{} { return lbl })
					}
					if lbl != "" {
						outputEntry[rule.AddSubnetLabel.Output] = lbl
					}
				}
			}
		case api.NetworkDecodeTCPFlags:
			if anyFlags, ok := outputEntry[rule.DecodeTCPFlags.Input]; ok && anyFlags != nil {
				if flags, err := util.ConvertToUint(anyFlags); err == nil {
					strFlags := util.DecodeTCPFlags(flags)
					// If input==output (ie. we're rewritting in place), always write the result even if empty/nil, to avoid having inconsistent output types
					if len(strFlags) > 0 || rule.DecodeTCPFlags.Output == rule.DecodeTCPFlags.Input {
						outputEntry[rule.DecodeTCPFlags.Output] = strFlags
					}
				}
			}

		default:
			log.Panicf("unknown type %s for transform.Network rule: %v", rule.Type, rule)
		}
	}

	return outputEntry, true
}

func (n *Network) applySubnetLabel(strIP string) string {
	ip := net.ParseIP(strIP)
	if ip != nil {
		for _, subnetCat := range n.snLabels {
			for _, cidr := range subnetCat.cidrs {
				if cidr.Contains(ip) {
					return subnetCat.name
				}
			}
		}
	}
	return ""
}

func parseSubnets(cfg *api.TransformNetwork) ([]subnetLabel, error) {
	var subnetCats []subnetLabel
	for _, category := range cfg.SubnetLabels {
		var cidrs []*net.IPNet
		for _, cidr := range category.CIDRs {
			_, parsed, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("category %s: fail to parse CIDR, %w", category.Name, err)
			}
			cidrs = append(cidrs, parsed)
		}
		if len(cidrs) > 0 {
			subnetCats = append(subnetCats, subnetLabel{name: category.Name, cidrs: cidrs})
		}
	}
	return subnetCats, nil
}

// Update: only reconfigure subnet labels
func (n *Network) Update(stage config.StageParam) {
	cfg := api.TransformNetwork{}
	if stage.Transform != nil && stage.Transform.Network != nil {
		cfg = *stage.Transform.Network
	}
	cfg.Preprocess()

	subnetCats, err := parseSubnets(&cfg)
	if err != nil {
		tlog.Errorf("Received invalid config update: %v - error: %v", cfg, err)
		return
	}

	tlog.Infof("Received config update: %v", cfg)
	if !reflect.DeepEqual(cfg.Rules, n.Rules) {
		tlog.Warn("Configured rules have changed: feature not implemented")
	}
	if !reflect.DeepEqual(cfg.DirectionInfo, n.DirectionInfo) {
		tlog.Warn("Configured directionInfo has changed: feature not implemented")
	}

	n.m.Lock()
	defer n.m.Unlock()
	n.snLabels = subnetCats
	n.ipLabelCache.Clear()
}

func initNetworkServices(cfg *api.TransformNetwork) (*netdb.ServiceNames, error) {
	pFilename, sFilename := cfg.GetServiceFiles()
	var err error
	protos, err := os.Open(pFilename)
	if err != nil {
		return nil, fmt.Errorf("opening protocols file %q: %w", pFilename, err)
	}
	defer protos.Close()
	services, err := os.Open(sFilename)
	if err != nil {
		return nil, fmt.Errorf("opening services file %q: %w", sFilename, err)
	}
	defer services.Close()
	return netdb.LoadServicesDB(protos, services)
}

// NewTransformNetwork create a new network transform
func NewTransformNetwork(params config.StageParam, opMetrics *operational.Metrics) (Transformer, error) {
	var locationDBConfig *api.NetworkAddLocationRule
	var needToInitKubeData = false
	var needToInitNetworkServices = false

	jsonNetworkTransform := api.TransformNetwork{}
	if params.Transform != nil && params.Transform.Network != nil {
		jsonNetworkTransform = *params.Transform.Network
	}
	jsonNetworkTransform.Preprocess()

	for _, rule := range jsonNetworkTransform.Rules {
		switch rule.Type {
		case api.NetworkAddLocation:
			if rule.AddLocation == nil {
				return nil, fmt.Errorf("missing configuration for '%s' rule", api.NetworkAddLocation)
			}
			locationDBConfig = rule.AddLocation
		case api.NetworkAddKubernetes:
			needToInitKubeData = true
		case api.NetworkAddKubernetesInfra:
			needToInitKubeData = true
		case api.NetworkAddService:
			needToInitNetworkServices = true
		case api.NetworkReinterpretDirection:
			if err := validateReinterpretDirectionConfig(&jsonNetworkTransform.DirectionInfo); err != nil {
				return nil, err
			}
		case api.NetworkAddSubnetLabel, api.NetworkAddSubnet, api.NetworkDecodeTCPFlags:
			// nothing
		}
	}

	if locationDBConfig != nil {
		err := location.InitLocationDB(locationDBConfig.FilePath)
		if err != nil {
			log.Warnf("location.InitLocationDB error: %v", err)
		}
	}

	if needToInitKubeData {
		err := kubernetes.InitInformerDatasource(&jsonNetworkTransform.KubeConfig, opMetrics)
		if err != nil {
			return nil, err
		}
	}

	var servicesDB *netdb.ServiceNames
	if needToInitNetworkServices {
		db, err := initNetworkServices(&jsonNetworkTransform)
		if err != nil {
			return nil, err
		}
		servicesDB = db
	}

	subnetCats, err := parseSubnets(&jsonNetworkTransform)
	if err != nil {
		return nil, err
	}

	return &Network{
		TransformNetwork: api.TransformNetwork{
			Rules:         jsonNetworkTransform.Rules,
			DirectionInfo: jsonNetworkTransform.DirectionInfo,
		},
		svcNames:     servicesDB,
		snLabels:     subnetCats,
		ipLabelCache: utils.NewQuietExpiringTimedCache(2 * time.Minute),
	}, nil
}
