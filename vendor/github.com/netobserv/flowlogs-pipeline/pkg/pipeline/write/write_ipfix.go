/*
 * Copyright (C) 2024 IBM, Inc.
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

package write

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/utils"
	"github.com/sirupsen/logrus"
	"github.com/vmware/go-ipfix/pkg/entities"
	ipfixExporter "github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
)

type writeIpfix struct {
	templateIDv4 uint16
	templateIDv6 uint16
	exporter     *ipfixExporter.ExportingProcess
	tplV4        entities.Set
	tplV6        entities.Set
	entitiesV4   []entities.InfoElementWithValue
	entitiesV6   []entities.InfoElementWithValue
}

type FieldMap struct {
	Key     string
	Getter  func(entities.InfoElementWithValue) any
	Setter  func(entities.InfoElementWithValue, any)
	Matcher func(entities.InfoElementWithValue, any) bool
	Default func(entities.InfoElementWithValue)
}

// IPv6Type value as defined in IEEE 802: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
const IPv6Type uint16 = 0x86DD

var (
	ilog = logrus.WithField("component", "write.Ipfix")
	// See RFC 5102: https://www.rfc-editor.org/rfc/rfc5102
	IANAFields = []string{
		"ethernetType",
		"flowDirection",
		"sourceMacAddress",
		"destinationMacAddress",
		"protocolIdentifier",
		"sourceTransportPort",
		"destinationTransportPort",
		"octetDeltaCount",
		"flowStartMilliseconds",
		"flowEndMilliseconds",
		"packetDeltaCount",
		"interfaceName",
		"tcpControlBits",
		"postNAPTSourceTransportPort",
		"postNAPTDestinationTransportPort",
	}
	IPv4IANAFields = append([]string{
		"sourceIPv4Address",
		"destinationIPv4Address",
		"icmpTypeIPv4",
		"icmpCodeIPv4",
		"postNATSourceIPv4Address",
		"postNATDestinationIPv4Address",
	}, IANAFields...)
	IPv6IANAFields = append([]string{
		"sourceIPv6Address",
		"destinationIPv6Address",
		"nextHeaderIPv6",
		"icmpTypeIPv6",
		"icmpCodeIPv6",
		"postNATSourceIPv6Address",
		"postNATDestinationIPv6Address",
	}, IANAFields...)
	KubeFields = []entities.InfoElement{
		{Name: "sourcePodNamespace", ElementId: 7733, DataType: entities.String, Len: 65535},
		{Name: "sourcePodName", ElementId: 7734, DataType: entities.String, Len: 65535},
		{Name: "destinationPodNamespace", ElementId: 7735, DataType: entities.String, Len: 65535},
		{Name: "destinationPodName", ElementId: 7736, DataType: entities.String, Len: 65535},
		{Name: "sourceNodeName", ElementId: 7737, DataType: entities.String, Len: 65535},
		{Name: "destinationNodeName", ElementId: 7738, DataType: entities.String, Len: 65535},
	}
	CustomNetworkFields = []entities.InfoElement{
		{Name: "timeFlowRttNs", ElementId: 7740, DataType: entities.Unsigned64, Len: 8},
		{Name: "interfaces", ElementId: 7741, DataType: entities.String, Len: 65535},
		{Name: "directions", ElementId: 7742, DataType: entities.String, Len: 65535},
	}
	CustomNetworkFieldsV4 = []entities.InfoElement{}
	CustomNetworkFieldsV6 = []entities.InfoElement{}

	MapIPFIXKeys = map[string]FieldMap{
		"sourceIPv4Address": {
			Key:    "SrcAddr",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetIPAddressValue().String() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetIPAddressValue(net.ParseIP(rec.(string))) },
		},
		"destinationIPv4Address": {
			Key:    "DstAddr",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetIPAddressValue().String() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetIPAddressValue(net.ParseIP(rec.(string))) },
		},
		"sourceIPv6Address": {
			Key:    "SrcAddr",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetIPAddressValue().String() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetIPAddressValue(net.ParseIP(rec.(string))) },
		},
		"destinationIPv6Address": {
			Key:    "DstAddr",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetIPAddressValue().String() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetIPAddressValue(net.ParseIP(rec.(string))) },
		},
		"nextHeaderIPv6": {
			Key:    "Proto",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetUnsigned8Value() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned8Value(rec.(uint8)) },
		},
		"sourceMacAddress": {
			Key:    "SrcMac",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetMacAddressValue().String() },
			Setter: func(elt entities.InfoElementWithValue, rec any) {
				mac, _ := net.ParseMAC(rec.(string))
				elt.SetMacAddressValue(mac)
			},
		},
		"destinationMacAddress": {
			Key:    "DstMac",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetMacAddressValue().String() },
			Setter: func(elt entities.InfoElementWithValue, rec any) {
				mac, _ := net.ParseMAC(rec.(string))
				elt.SetMacAddressValue(mac)
			},
		},
		"ethernetType": {
			Key:    "Etype",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetUnsigned16Value() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned16Value(rec.(uint16)) },
		},
		"flowDirection": {
			Key: "IfDirections",
			Setter: func(elt entities.InfoElementWithValue, rec any) {
				if dirs, ok := rec.([]int); ok && len(dirs) > 0 {
					elt.SetUnsigned8Value(uint8(dirs[0]))
				}
			},
			Matcher: func(elt entities.InfoElementWithValue, expected any) bool {
				ifdirs := expected.([]int)
				return int(elt.GetUnsigned8Value()) == ifdirs[0]
			},
		},
		"directions": {
			Key: "IfDirections",
			Getter: func(elt entities.InfoElementWithValue) any {
				var dirs []int
				for _, dir := range strings.Split(elt.GetStringValue(), ",") {
					d, _ := strconv.Atoi(dir)
					dirs = append(dirs, d)
				}
				return dirs
			},
			Setter: func(elt entities.InfoElementWithValue, rec any) {
				if dirs, ok := rec.([]int); ok && len(dirs) > 0 {
					var asStr []string
					for _, dir := range dirs {
						asStr = append(asStr, strconv.Itoa(dir))
					}
					elt.SetStringValue(strings.Join(asStr, ","))
				}
			},
		},
		"protocolIdentifier": {
			Key:    "Proto",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetUnsigned8Value() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned8Value(rec.(uint8)) },
		},
		"sourceTransportPort": {
			Key:    "SrcPort",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetUnsigned16Value() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned16Value(rec.(uint16)) },
		},
		"destinationTransportPort": {
			Key:    "DstPort",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetUnsigned16Value() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned16Value(rec.(uint16)) },
		},
		"octetDeltaCount": {
			Key:    "Bytes",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetUnsigned64Value() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned64Value(rec.(uint64)) },
		},
		"flowStartMilliseconds": {
			Key:    "TimeFlowStartMs",
			Getter: func(elt entities.InfoElementWithValue) any { return int64(elt.GetUnsigned64Value()) },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned64Value(uint64(rec.(int64))) },
		},
		"flowEndMilliseconds": {
			Key:    "TimeFlowEndMs",
			Getter: func(elt entities.InfoElementWithValue) any { return int64(elt.GetUnsigned64Value()) },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned64Value(uint64(rec.(int64))) },
		},
		"packetDeltaCount": {
			Key:    "Packets",
			Getter: func(elt entities.InfoElementWithValue) any { return uint32(elt.GetUnsigned64Value()) },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned64Value(uint64(rec.(uint32))) },
		},
		"interfaceName": {
			Key: "Interfaces",
			Setter: func(elt entities.InfoElementWithValue, rec any) {
				if ifs, ok := rec.([]string); ok && len(ifs) > 0 {
					elt.SetStringValue(ifs[0])
				}
			},
			Matcher: func(elt entities.InfoElementWithValue, expected any) bool {
				ifs := expected.([]string)
				return elt.GetStringValue() == ifs[0]
			},
		},
		"tcpControlBits": {
			Key: "Flags",
			Getter: func(elt entities.InfoElementWithValue) any {
				return elt.GetUnsigned16Value()
			},
			Setter: func(elt entities.InfoElementWithValue, rec any) {
				if decoded, isDecoded := rec.([]string); isDecoded {
					// reencode for ipfix
					reencoded := utils.EncodeTCPFlags(decoded)
					elt.SetUnsigned16Value(uint16(reencoded))
				} else if raw, isRaw := rec.(uint16); isRaw {
					elt.SetUnsigned16Value(raw)
				}
			},
			Matcher: func(elt entities.InfoElementWithValue, expected any) bool {
				received := elt.GetUnsigned16Value()
				if expSlice, isSlice := expected.([]string); isSlice {
					decoded := utils.DecodeTCPFlags(uint(received))
					if len(expSlice) != len(decoded) {
						return false
					}
					for i := 0; i < len(expSlice); i++ {
						if expSlice[i] != decoded[i] {
							return false
						}
					}
					return true
				}
				if expected == nil {
					return received == 0
				}
				return received == expected
			},
		},
		"icmpTypeIPv4": {
			Key:    "IcmpType",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetUnsigned8Value() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned8Value(rec.(uint8)) },
		},
		"icmpCodeIPv4": {
			Key:    "IcmpCode",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetUnsigned8Value() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned8Value(rec.(uint8)) },
		},
		"icmpTypeIPv6": {
			Key:    "IcmpType",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetUnsigned8Value() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned8Value(rec.(uint8)) },
		},
		"icmpCodeIPv6": {
			Key:    "IcmpCode",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetUnsigned8Value() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned8Value(rec.(uint8)) },
		},
		"interfaces": {
			Key:    "Interfaces",
			Getter: func(elt entities.InfoElementWithValue) any { return strings.Split(elt.GetStringValue(), ",") },
			Setter: func(elt entities.InfoElementWithValue, rec any) {
				if ifs, ok := rec.([]string); ok {
					elt.SetStringValue(strings.Join(ifs, ","))
				}
			},
		},
		"sourcePodNamespace": {
			Key:    "SrcK8S_Namespace",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetStringValue() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetStringValue(rec.(string)) },
		},
		"sourcePodName": {
			Key:    "SrcK8S_Name",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetStringValue() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetStringValue(rec.(string)) },
		},
		"destinationPodNamespace": {
			Key:    "DstK8S_Namespace",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetStringValue() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetStringValue(rec.(string)) },
		},
		"destinationPodName": {
			Key:    "DstK8S_Name",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetStringValue() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetStringValue(rec.(string)) },
		},
		"sourceNodeName": {
			Key:    "SrcK8S_HostName",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetStringValue() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetStringValue(rec.(string)) },
		},
		"destinationNodeName": {
			Key:    "DstK8S_HostName",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetStringValue() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetStringValue(rec.(string)) },
		},
		"timeFlowRttNs": {
			Key:    "TimeFlowRttNs",
			Getter: func(elt entities.InfoElementWithValue) any { return int64(elt.GetUnsigned64Value()) },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned64Value(uint64(rec.(int64))) },
		},
		"postNAPTSourceTransportPort": {
			Key:    "XlatSrcPort",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetUnsigned16Value() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned16Value(rec.(uint16)) },
		},
		"postNAPTDestinationTransportPort": {
			Key:    "XlatDstPort",
			Getter: func(elt entities.InfoElementWithValue) any { return elt.GetUnsigned16Value() },
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetUnsigned16Value(rec.(uint16)) },
		},
		"postNATSourceIPv4Address": {
			Key: "XlatSrcAddr",
			Getter: func(elt entities.InfoElementWithValue) any {
				if net.IPv4zero.Equal(elt.GetIPAddressValue()) {
					return nil
				}
				return elt.GetIPAddressValue().String()
			},
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetIPAddressValue(net.ParseIP(rec.(string))) },
			// Force zero-IP by default to avoid go-ipfix throwing an error: https://github.com/vmware/go-ipfix/blob/d9256ccb0ed9e3ae38c3a2bf3d6ce1ce01c9ac4f/pkg/entities/ie.go#L596
			Default: func(elt entities.InfoElementWithValue) { elt.SetIPAddressValue(net.IPv4zero) },
		},
		"postNATDestinationIPv4Address": {
			Key: "XlatDstAddr",
			Getter: func(elt entities.InfoElementWithValue) any {
				if net.IPv4zero.Equal(elt.GetIPAddressValue()) {
					return nil
				}
				return elt.GetIPAddressValue().String()
			},
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetIPAddressValue(net.ParseIP(rec.(string))) },
			// Force zero-IP by default to avoid go-ipfix throwing an error: https://github.com/vmware/go-ipfix/blob/d9256ccb0ed9e3ae38c3a2bf3d6ce1ce01c9ac4f/pkg/entities/ie.go#L596
			Default: func(elt entities.InfoElementWithValue) { elt.SetIPAddressValue(net.IPv4zero) },
		},
		"postNATSourceIPv6Address": {
			Key: "XlatSrcAddr",
			Getter: func(elt entities.InfoElementWithValue) any {
				if net.IPv6zero.Equal(elt.GetIPAddressValue()) {
					return nil
				}
				return elt.GetIPAddressValue().String()
			},
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetIPAddressValue(net.ParseIP(rec.(string))) },
			// Force zero-IP by default to avoid go-ipfix throwing an error: https://github.com/vmware/go-ipfix/blob/d9256ccb0ed9e3ae38c3a2bf3d6ce1ce01c9ac4f/pkg/entities/ie.go#L602
			Default: func(elt entities.InfoElementWithValue) { elt.SetIPAddressValue(net.IPv6zero) },
		},
		"postNATDestinationIPv6Address": {
			Key: "XlatDstAddr",
			Getter: func(elt entities.InfoElementWithValue) any {
				if net.IPv6zero.Equal(elt.GetIPAddressValue()) {
					return nil
				}
				return elt.GetIPAddressValue().String()
			},
			Setter: func(elt entities.InfoElementWithValue, rec any) { elt.SetIPAddressValue(net.ParseIP(rec.(string))) },
			// Force zero-IP by default to avoid go-ipfix throwing an error: https://github.com/vmware/go-ipfix/blob/d9256ccb0ed9e3ae38c3a2bf3d6ce1ce01c9ac4f/pkg/entities/ie.go#L602
			Default: func(elt entities.InfoElementWithValue) { elt.SetIPAddressValue(net.IPv6zero) },
		},
	}
)

func addElementToTemplate(elementName string, value []byte, elements *[]entities.InfoElementWithValue, registryID uint32) error {
	element, err := registry.GetInfoElement(elementName, registryID)
	if err != nil {
		ilog.WithError(err).Errorf("Did not find the element with name %s", elementName)
		return err
	}
	ie, err := entities.DecodeAndCreateInfoElementWithValue(element, value)
	if err != nil {
		ilog.WithError(err).Errorf("Failed to decode element %s", elementName)
		return err
	}
	*elements = append(*elements, ie)
	return nil
}

func addNetworkEnrichmentToTemplate(elements *[]entities.InfoElementWithValue, registryID uint32, v6 bool) error {
	fields := CustomNetworkFields
	if v6 {
		fields = append(fields, CustomNetworkFieldsV6...)
	} else {
		fields = append(fields, CustomNetworkFieldsV4...)
	}
	for _, field := range fields {
		if err := addElementToTemplate(field.Name, nil, elements, registryID); err != nil {
			return err
		}
	}
	return nil
}

func addKubeContextToTemplate(elements *[]entities.InfoElementWithValue, registryID uint32) error {
	for _, field := range KubeFields {
		if err := addElementToTemplate(field.Name, nil, elements, registryID); err != nil {
			return err
		}
	}
	return nil
}

func loadCustomRegistry(enterpriseID uint32) error {
	err := registry.InitNewRegistry(enterpriseID)
	if err != nil {
		ilog.WithError(err).Errorf("Failed to initialize registry")
		return err
	}
	allCustom := []entities.InfoElement{}
	allCustom = append(allCustom, KubeFields...)
	allCustom = append(allCustom, CustomNetworkFields...)
	allCustom = append(allCustom, CustomNetworkFieldsV4...)
	allCustom = append(allCustom, CustomNetworkFieldsV6...)
	for _, f := range allCustom {
		f.EnterpriseId = enterpriseID
		err = registry.PutInfoElement(f, enterpriseID)
		if err != nil {
			ilog.WithError(err).Errorf("Failed to register element: %s", f.Name)
			return err
		}
	}
	return nil
}

func prepareTemplate(templateID uint16, enrichEnterpriseID uint32, v6 bool) (entities.Set, []entities.InfoElementWithValue, error) {
	templateSet := entities.NewSet(false)
	err := templateSet.PrepareSet(entities.Template, templateID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare set (v6=%t), %w", v6, err)
	}
	elements := make([]entities.InfoElementWithValue, 0)
	var fields []string
	if v6 {
		fields = IPv6IANAFields
	} else {
		fields = IPv4IANAFields
	}

	for _, field := range fields {
		err = addElementToTemplate(field, nil, &elements, registry.IANAEnterpriseID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to add %s to template (v6=%t), %w", field, v6, err)
		}
	}
	if enrichEnterpriseID != 0 {
		err = addKubeContextToTemplate(&elements, enrichEnterpriseID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to add k8s context (v6=%t), %w", v6, err)
		}
		err = addNetworkEnrichmentToTemplate(&elements, enrichEnterpriseID, v6)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to add network enrichment (v6=%t), %w", v6, err)
		}
	}
	err = templateSet.AddRecord(elements, templateID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to add record (v6=%t), %w", v6, err)
	}

	return templateSet, elements, nil
}

func createDataRecord(flow config.GenericMap, elements []entities.InfoElementWithValue) {
	for _, ieVal := range elements {
		name := ieVal.GetName()
		if mapping, ok := MapIPFIXKeys[name]; ok {
			if value := flow[mapping.Key]; value != nil {
				mapping.Setter(ieVal, value)
			} else if mapping.Default != nil {
				mapping.Default(ieVal)
			}
		}
	}
}

func (t *writeIpfix) sendDataRecord(record config.GenericMap, v6 bool) error {
	dataSet := entities.NewSet(false)
	var dataRecord []entities.InfoElementWithValue
	var templateID uint16
	if v6 {
		templateID = t.templateIDv6
		dataRecord = t.entitiesV6
	} else {
		templateID = t.templateIDv4
		dataRecord = t.entitiesV4
	}
	createDataRecord(record, dataRecord)
	err := dataSet.PrepareSet(entities.Data, templateID)
	if err != nil {
		return fmt.Errorf("failed to prepare set (v6: %t): %w", v6, err)
	}
	err = dataSet.AddRecord(dataRecord, templateID)
	if err != nil {
		return fmt.Errorf("failed to add record (v6: %t): %w", v6, err)
	}
	_, err = t.exporter.SendSet(dataSet)
	if err != nil {
		return fmt.Errorf("failed to send set (v6: %t): %w", v6, err)
	}
	return nil
}

// Write writes a flow before being stored
func (t *writeIpfix) Write(entry config.GenericMap) {
	if IPv6Type == entry["Etype"].(uint16) {
		err := t.sendDataRecord(entry, true)
		if err != nil {
			ilog.WithError(err).Error("Failed in send v6 IPFIX record")
		}
	} else {
		err := t.sendDataRecord(entry, false)
		if err != nil {
			ilog.WithError(err).Error("Failed in send v4 IPFIX record")
		}
	}
}

// NewWriteIpfix creates a new write
func NewWriteIpfix(params config.StageParam) (Writer, error) {
	ipfixConfigIn := api.WriteIpfix{}
	if params.Write != nil && params.Write.Ipfix != nil {
		ipfixConfigIn = *params.Write.Ipfix
	}
	// need to combine defaults with parameters that are provided in the config yaml file
	ipfixConfigIn.SetDefaults()

	if err := ipfixConfigIn.Validate(); err != nil {
		return nil, fmt.Errorf("the provided config is not valid: %w", err)
	}

	// Create exporter using local server info
	input := ipfixExporter.ExporterInput{
		CollectorAddress:    fmt.Sprintf("%s:%d", ipfixConfigIn.TargetHost, ipfixConfigIn.TargetPort),
		CollectorProtocol:   ipfixConfigIn.Transport,
		ObservationDomainID: 1,
		TempRefTimeout:      uint32(ipfixConfigIn.TplSendInterval.Duration.Seconds()),
	}

	exporter, err := ipfixExporter.InitExportingProcess(input)
	if err != nil {
		return nil, fmt.Errorf("error when connecting to IPFIX collector %s: %w", input.CollectorAddress, err)
	}
	ilog.Infof("Created IPFIX exporter connecting to server with address: %s", input.CollectorAddress)

	eeid := uint32(ipfixConfigIn.EnterpriseID)

	registry.LoadRegistry()
	if eeid != 0 {
		if err := loadCustomRegistry(eeid); err != nil {
			return nil, fmt.Errorf("failed to load custom registry with EnterpriseID=%d: %w", eeid, err)
		}
	}

	idV4 := exporter.NewTemplateID()
	setV4, entitiesV4, err := prepareTemplate(idV4, eeid, false)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare IPv4 template: %w", err)
	}

	idV6 := exporter.NewTemplateID()
	setV6, entitiesV6, err := prepareTemplate(idV6, eeid, true)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare IPv6 template: %w", err)
	}

	// First send sync
	if _, err := exporter.SendSet(setV4); err != nil {
		return nil, fmt.Errorf("failed to send IPv4 template: %w", err)
	}
	if _, err := exporter.SendSet(setV6); err != nil {
		return nil, fmt.Errorf("failed to send IPv6 template: %w", err)
	}

	writeIpfix := &writeIpfix{
		exporter:     exporter,
		templateIDv4: idV4,
		tplV4:        setV4,
		entitiesV4:   entitiesV4,
		templateIDv6: idV6,
		tplV6:        setV6,
		entitiesV6:   entitiesV6,
	}

	return writeIpfix, nil
}
