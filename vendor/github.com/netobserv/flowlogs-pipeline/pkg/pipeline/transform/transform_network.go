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
	"strconv"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/transform/kubernetes"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/transform/location"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/transform/netdb"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/utils"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("component", "transform.Network")

type Network struct {
	api.TransformNetwork
	svcNames   *netdb.ServiceNames
	categories []subnetCategory
	ipCatCache *utils.TimedCache
}

type subnetCategory struct {
	cidrs []*net.IPNet
	name  string
}

func (n *Network) Transform(inputEntry config.GenericMap) (config.GenericMap, bool) {
	// copy input entry before transform to avoid alteration on parallel stages
	outputEntry := inputEntry.Copy()

	// TODO: for efficiency and maintainability, maybe each case in the switch below should be an individual implementation of Transformer
	for _, rule := range n.Rules {
		switch rule.Type {
		case api.OpAddSubnet:
			_, ipv4Net, err := net.ParseCIDR(fmt.Sprintf("%v%s", outputEntry[rule.Input], rule.Parameters))
			if err != nil {
				log.Warningf("Can't find subnet for IP %v and prefix length %s - err %v", outputEntry[rule.Input], rule.Parameters, err)
				continue
			}
			outputEntry[rule.Output] = ipv4Net.String()
		case api.OpAddLocation:
			var locationInfo *location.Info
			err, locationInfo := location.GetLocation(fmt.Sprintf("%s", outputEntry[rule.Input]))
			if err != nil {
				log.Warningf("Can't find location for IP %v err %v", outputEntry[rule.Input], err)
				continue
			}
			outputEntry[rule.Output+"_CountryName"] = locationInfo.CountryName
			outputEntry[rule.Output+"_CountryLongName"] = locationInfo.CountryLongName
			outputEntry[rule.Output+"_RegionName"] = locationInfo.RegionName
			outputEntry[rule.Output+"_CityName"] = locationInfo.CityName
			outputEntry[rule.Output+"_Latitude"] = locationInfo.Latitude
			outputEntry[rule.Output+"_Longitude"] = locationInfo.Longitude
		case api.OpAddService:
			protocol := fmt.Sprintf("%v", outputEntry[rule.Parameters])
			portNumber, err := strconv.Atoi(fmt.Sprintf("%v", outputEntry[rule.Input]))
			if err != nil {
				log.Errorf("Can't convert port to int: Port %v - err %v", outputEntry[rule.Input], err)
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
					log.Debugf("Can't find service name for Port %v and protocol %v - err %v", outputEntry[rule.Input], protocol, err)
					continue
				}
			}
			outputEntry[rule.Output] = serviceName
		case api.OpAddKubernetes:
			kubeInfo, err := kubernetes.Data.GetInfo(fmt.Sprintf("%s", outputEntry[rule.Input]))
			if err != nil {
				logrus.WithError(err).Tracef("can't find kubernetes info for IP %v", outputEntry[rule.Input])
				continue
			}
			// NETOBSERV-666: avoid putting empty namespaces or Loki aggregation queries will
			// differentiate between empty and nil namespaces.
			if kubeInfo.Namespace != "" {
				outputEntry[rule.Output+"_Namespace"] = kubeInfo.Namespace
			}
			outputEntry[rule.Output+"_Name"] = kubeInfo.Name
			outputEntry[rule.Output+"_Type"] = kubeInfo.Type
			outputEntry[rule.Output+"_OwnerName"] = kubeInfo.Owner.Name
			outputEntry[rule.Output+"_OwnerType"] = kubeInfo.Owner.Type
			if rule.Parameters != "" {
				for labelKey, labelValue := range kubeInfo.Labels {
					outputEntry[rule.Parameters+"_"+labelKey] = labelValue
				}
			}
			if kubeInfo.HostIP != "" {
				outputEntry[rule.Output+"_HostIP"] = kubeInfo.HostIP
				if kubeInfo.HostName != "" {
					outputEntry[rule.Output+"_HostName"] = kubeInfo.HostName
				}
			}
		case api.OpReinterpretDirection:
			reinterpretDirection(outputEntry, &n.DirectionInfo)
		case api.OpAddIPCategory:
			if strIP, ok := outputEntry[rule.Input].(string); ok {
				cat, ok := n.ipCatCache.GetCacheEntry(strIP)
				if !ok {
					cat = n.categorizeIP(net.ParseIP(strIP))
					n.ipCatCache.UpdateCacheEntry(strIP, cat)
				}
				outputEntry[rule.Output] = cat
			}

		default:
			log.Panicf("unknown type %s for transform.Network rule: %v", rule.Type, rule)
		}
	}

	return outputEntry, true
}

func (n *Network) categorizeIP(ip net.IP) string {
	if ip != nil {
		for _, subnetCat := range n.categories {
			for _, cidr := range subnetCat.cidrs {
				if cidr.Contains(ip) {
					return subnetCat.name
				}
			}
		}
	}
	return ""
}

// NewTransformNetwork create a new transform
func NewTransformNetwork(params config.StageParam) (Transformer, error) {
	var needToInitLocationDB = false
	var needToInitKubeData = false
	var needToInitNetworkServices = false

	jsonNetworkTransform := api.TransformNetwork{}
	if params.Transform != nil && params.Transform.Network != nil {
		jsonNetworkTransform = *params.Transform.Network
	}
	for _, rule := range jsonNetworkTransform.Rules {
		switch rule.Type {
		case api.OpAddLocation:
			needToInitLocationDB = true
		case api.OpAddKubernetes:
			needToInitKubeData = true
		case api.OpAddService:
			needToInitNetworkServices = true
		case api.OpReinterpretDirection:
			if err := validateReinterpretDirectionConfig(&jsonNetworkTransform.DirectionInfo); err != nil {
				return nil, err
			}
		case api.OpAddIPCategory:
			if len(jsonNetworkTransform.IPCategories) == 0 {
				return nil, fmt.Errorf("a rule '%s' was found, but there are no IP categories configured", api.OpAddIPCategory)
			}
		}
	}

	if needToInitLocationDB {
		err := location.InitLocationDB()
		if err != nil {
			log.Debugf("location.InitLocationDB error: %v", err)
		}
	}

	if needToInitKubeData {
		err := kubernetes.Data.InitFromConfig(jsonNetworkTransform.KubeConfigPath)
		if err != nil {
			return nil, err
		}
	}

	var servicesDB *netdb.ServiceNames
	if needToInitNetworkServices {
		pFilename, sFilename := jsonNetworkTransform.GetServiceFiles()
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
		servicesDB, err = netdb.LoadServicesDB(protos, services)
		if err != nil {
			return nil, err
		}
	}

	var subnetCats []subnetCategory
	for _, category := range jsonNetworkTransform.IPCategories {
		var cidrs []*net.IPNet
		for _, cidr := range category.CIDRs {
			_, parsed, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("category %s: fail to parse CIDR, %w", category.Name, err)
			}
			cidrs = append(cidrs, parsed)
		}
		if len(cidrs) > 0 {
			subnetCats = append(subnetCats, subnetCategory{name: category.Name, cidrs: cidrs})
		}
	}

	return &Network{
		TransformNetwork: api.TransformNetwork{
			Rules:         jsonNetworkTransform.Rules,
			DirectionInfo: jsonNetworkTransform.DirectionInfo,
		},
		svcNames:   servicesDB,
		categories: subnetCats,
		ipCatCache: utils.NewQuietExpiringTimedCache(2 * time.Minute),
	}, nil
}
