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

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/sirupsen/logrus"
	"github.com/vmware/go-ipfix/pkg/entities"
	ipfixExporter "github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
)

type writeIpfix struct {
	hostPort           string
	transport          string
	templateIDv4       uint16
	templateIDv6       uint16
	enrichEnterpriseID uint32
	exporter           *ipfixExporter.ExportingProcess
	entitiesV4         []entities.InfoElementWithValue
	entitiesV6         []entities.InfoElementWithValue
}

// IPv6Type value as defined in IEEE 802: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
const IPv6Type = 0x86DD

var (
	ilog       = logrus.WithField("component", "write.Ipfix")
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
	}
	IPv4IANAFields = append([]string{
		"sourceIPv4Address",
		"destinationIPv4Address",
	}, IANAFields...)
	IPv6IANAFields = append([]string{
		"sourceIPv6Address",
		"destinationIPv6Address",
		"nextHeaderIPv6",
	}, IANAFields...)
	KubeFields = []string{
		"sourcePodNamespace",
		"sourcePodName",
		"destinationPodNamespace",
		"destinationPodName",
		"sourceNodeName",
		"destinationNodeName",
	}
	CustomNetworkFields = []string{
		"timeFlowRttNs",
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

func addNetworkEnrichmentToTemplate(elements *[]entities.InfoElementWithValue, registryID uint32) error {
	for _, field := range CustomNetworkFields {
		if err := addElementToTemplate(field, nil, elements, registryID); err != nil {
			return err
		}
	}
	return nil
}

func addKubeContextToTemplate(elements *[]entities.InfoElementWithValue, registryID uint32) error {
	for _, field := range KubeFields {
		if err := addElementToTemplate(field, nil, elements, registryID); err != nil {
			return err
		}
	}
	return nil
}

func loadCustomRegistry(EnterpriseID uint32) error {
	err := registry.InitNewRegistry(EnterpriseID)
	if err != nil {
		ilog.WithError(err).Errorf("Failed to initialize registry")
		return err
	}
	err = registry.PutInfoElement((*entities.NewInfoElement("sourcePodNamespace", 7733, entities.String, EnterpriseID, 65535)), EnterpriseID)
	if err != nil {
		ilog.WithError(err).Errorf("Failed to register element")
		return err
	}
	err = registry.PutInfoElement((*entities.NewInfoElement("sourcePodName", 7734, entities.String, EnterpriseID, 65535)), EnterpriseID)
	if err != nil {
		ilog.WithError(err).Errorf("Failed to register element")
		return err
	}
	err = registry.PutInfoElement((*entities.NewInfoElement("destinationPodNamespace", 7735, entities.String, EnterpriseID, 65535)), EnterpriseID)
	if err != nil {
		ilog.WithError(err).Errorf("Failed to register element")
		return err
	}
	err = registry.PutInfoElement((*entities.NewInfoElement("destinationPodName", 7736, entities.String, EnterpriseID, 65535)), EnterpriseID)
	if err != nil {
		ilog.WithError(err).Errorf("Failed to register element")
		return err
	}
	err = registry.PutInfoElement((*entities.NewInfoElement("sourceNodeName", 7737, entities.String, EnterpriseID, 65535)), EnterpriseID)
	if err != nil {
		ilog.WithError(err).Errorf("Failed to register element")
		return err
	}
	err = registry.PutInfoElement((*entities.NewInfoElement("destinationNodeName", 7738, entities.String, EnterpriseID, 65535)), EnterpriseID)
	if err != nil {
		ilog.WithError(err).Errorf("Failed to register element")
		return err
	}
	err = registry.PutInfoElement((*entities.NewInfoElement("timeFlowRttNs", 7740, entities.Unsigned64, EnterpriseID, 8)), EnterpriseID)
	if err != nil {
		ilog.WithError(err).Errorf("Failed to register element")
		return err
	}
	return nil
}

func SendTemplateRecordv4(exporter *ipfixExporter.ExportingProcess, enrichEnterpriseID uint32) (uint16, []entities.InfoElementWithValue, error) {
	templateID := exporter.NewTemplateID()
	templateSet := entities.NewSet(false)
	err := templateSet.PrepareSet(entities.Template, templateID)
	if err != nil {
		ilog.WithError(err).Error("Failed in PrepareSet")
		return 0, nil, err
	}
	elements := make([]entities.InfoElementWithValue, 0)

	for _, field := range IPv4IANAFields {
		err = addElementToTemplate(field, nil, &elements, registry.IANAEnterpriseID)
		if err != nil {
			return 0, nil, err
		}
	}
	if enrichEnterpriseID != 0 {
		err = addKubeContextToTemplate(&elements, enrichEnterpriseID)
		if err != nil {
			return 0, nil, err
		}
		err = addNetworkEnrichmentToTemplate(&elements, enrichEnterpriseID)
		if err != nil {
			return 0, nil, err
		}
	}
	err = templateSet.AddRecord(elements, templateID)
	if err != nil {
		ilog.WithError(err).Error("Failed in Add Record")
		return 0, nil, err
	}
	_, err = exporter.SendSet(templateSet)
	if err != nil {
		ilog.WithError(err).Error("Failed to send template record")
		return 0, nil, err
	}

	return templateID, elements, nil
}

func SendTemplateRecordv6(exporter *ipfixExporter.ExportingProcess, enrichEnterpriseID uint32) (uint16, []entities.InfoElementWithValue, error) {
	templateID := exporter.NewTemplateID()
	templateSet := entities.NewSet(false)
	err := templateSet.PrepareSet(entities.Template, templateID)
	if err != nil {
		return 0, nil, err
	}
	elements := make([]entities.InfoElementWithValue, 0)

	for _, field := range IPv6IANAFields {
		err = addElementToTemplate(field, nil, &elements, registry.IANAEnterpriseID)
		if err != nil {
			return 0, nil, err
		}
	}
	if enrichEnterpriseID != 0 {
		err = addKubeContextToTemplate(&elements, enrichEnterpriseID)
		if err != nil {
			return 0, nil, err
		}
		err = addNetworkEnrichmentToTemplate(&elements, enrichEnterpriseID)
		if err != nil {
			return 0, nil, err
		}
	}

	err = templateSet.AddRecord(elements, templateID)
	if err != nil {
		return 0, nil, err
	}
	_, err = exporter.SendSet(templateSet)
	if err != nil {
		return 0, nil, err
	}

	return templateID, elements, nil
}

func setStandardIEValue(record config.GenericMap, ieValPtr *entities.InfoElementWithValue) error {
	ieVal := *ieValPtr
	switch ieVal.GetName() {
	case "ethernetType":
		if record["Etype"] != nil {
			ieVal.SetUnsigned16Value(uint16(record["Etype"].(uint32)))
		} else {
			return fmt.Errorf("unable to find ethernet type (Etype) in record")
		}
	case "flowDirection":
		dirs := record["IfDirections"].([]int)
		if len(dirs) > 0 {
			ieVal.SetUnsigned8Value(uint8(dirs[0]))
		} else {
			return fmt.Errorf("unable to find flow direction (flowDirection) in record")
		}
	case "sourceMacAddress":
		if record["SrcMac"] != nil {
			ieVal.SetMacAddressValue(net.HardwareAddr(record["SrcMac"].(string)))
		} else {
			return fmt.Errorf("unable to find source mac address (SrcMac) in record")
		}
	case "destinationMacAddress":
		if record["DstMac"] != nil {
			ieVal.SetMacAddressValue(net.HardwareAddr(record["DstMac"].(string)))
		} else {
			return fmt.Errorf("unable to find dest mac address (DstMac) in record")
		}
	case "sourceIPv4Address":
		if record["SrcAddr"] != nil {
			ieVal.SetIPAddressValue(net.ParseIP(record["SrcAddr"].(string)))
		} else {
			return fmt.Errorf("unable to find source IPv4 address (SrcAddr) in record")
		}
	case "destinationIPv4Address":
		if record["DstAddr"] != nil {
			ieVal.SetIPAddressValue(net.ParseIP(record["DstAddr"].(string)))
		} else {
			return fmt.Errorf("unable to find dest IPv4 address (DstAddr) in record")
		}
	case "sourceIPv6Address":
		if record["SrcAddr"] != nil {
			ieVal.SetIPAddressValue(net.ParseIP(record["SrcAddr"].(string)))
		} else {
			return fmt.Errorf("unable to find source IPv6 address (SrcAddr) in record")
		}
	case "destinationIPv6Address":
		if record["DstAddr"] != nil {
			ieVal.SetIPAddressValue(net.ParseIP(record["DstAddr"].(string)))
		} else {
			return fmt.Errorf("unable to find dest IPv6 address (DstAddr) in record")
		}
	case "protocolIdentifier":
		if record["Proto"] != nil {
			ieVal.SetUnsigned8Value(uint8(record["Proto"].(uint32)))
		} else {
			return fmt.Errorf("unable to find protocol identifier (Proto) in record")
		}
	case "nextHeaderIPv6":
		if record["Proto"] != nil {
			ieVal.SetUnsigned8Value(uint8(record["Proto"].(uint32)))
		} else {
			return fmt.Errorf("unable to find next header (Proto) in record")
		}
	case "sourceTransportPort":
		if record["SrcPort"] != nil {
			ieVal.SetUnsigned16Value(uint16(record["SrcPort"].(uint32)))
		} else {
			return fmt.Errorf("unable to find source port (SrcPort) in record")
		}
	case "destinationTransportPort":
		if record["DstPort"] != nil {
			ieVal.SetUnsigned16Value(uint16(record["DstPort"].(uint32)))
		} else {
			return fmt.Errorf("unable to find dest port (DstPort) in record")
		}
	case "octetDeltaCount":
		if record["Bytes"] != nil {
			ieVal.SetUnsigned64Value(record["Bytes"].(uint64))
		} else {
			return fmt.Errorf("unable to find bytes in record")
		}
	case "flowStartMilliseconds":
		if record["TimeFlowStartMs"] != nil {
			ieVal.SetUnsigned64Value(uint64(record["TimeFlowStartMs"].(int64)))
		} else {
			return fmt.Errorf("unable to find flow start time (TimeFlowStartMs) in record")
		}
	case "flowEndMilliseconds":
		if record["TimeFlowEndMs"] != nil {
			ieVal.SetUnsigned64Value(uint64(record["TimeFlowEndMs"].(int64)))
		} else {
			return fmt.Errorf("unable to find flow end time (TimeFlowEndMs) in record")
		}
	case "packetDeltaCount":
		if record["Packets"] != nil {
			ieVal.SetUnsigned64Value(record["Packets"].(uint64))
		} else {
			return fmt.Errorf("unable to find packets in record")
		}
	case "interfaceName":
		interfaces := record["Interfaces"].([]string)
		if len(interfaces) > 0 {
			ieVal.SetStringValue(interfaces[0])
		} else {
			return fmt.Errorf("unable to find interface in record")
		}
	case "timeFlowRttNs":
		if record["TimeFlowRttNs"] != nil {
			ieVal.SetUnsigned64Value(uint64(record["TimeFlowRttNs"].(int64)))
		} else {
			return fmt.Errorf("unable to find timeflowrtt in record")
		}
	}
	return nil
}

func setKubeIEValue(record config.GenericMap, ieValPtr *entities.InfoElementWithValue) {
	ieVal := *ieValPtr
	switch ieVal.GetName() {
	case "sourcePodNamespace":
		if record["SrcK8S_Namespace"] != nil {
			ieVal.SetStringValue(record["SrcK8S_Namespace"].(string))
		} else {
			ieVal.SetStringValue("none")
		}
	case "sourcePodName":
		if record["SrcK8S_Name"] != nil {
			ieVal.SetStringValue(record["SrcK8S_Name"].(string))
		} else {
			ieVal.SetStringValue("none")
		}
	case "destinationPodNamespace":
		if record["DstK8S_Namespace"] != nil {
			ieVal.SetStringValue(record["DstK8S_Namespace"].(string))
		} else {
			ieVal.SetStringValue("none")
		}
	case "destinationPodName":
		if record["DstK8S_Name"] != nil {
			ieVal.SetStringValue(record["DstK8S_Name"].(string))
		} else {
			ieVal.SetStringValue("none")
		}
	case "sourceNodeName":
		if record["SrcK8S_HostName"] != nil {
			ieVal.SetStringValue(record["SrcK8S_HostName"].(string))
		} else {
			ieVal.SetStringValue("none")
		}
	case "destinationNodeName":
		if record["DstK8S_HostName"] != nil {
			ieVal.SetStringValue(record["DstK8S_HostName"].(string))
		} else {
			ieVal.SetStringValue("none")
		}
	}
}
func setEntities(record config.GenericMap, enrichEnterpriseID uint32, elements *[]entities.InfoElementWithValue) error {
	for _, ieVal := range *elements {
		err := setStandardIEValue(record, &ieVal)
		if err != nil {
			return err
		}
		if enrichEnterpriseID != 0 {
			setKubeIEValue(record, &ieVal)
		}
	}
	return nil
}
func (t *writeIpfix) sendDataRecord(record config.GenericMap, v6 bool) error {
	dataSet := entities.NewSet(false)
	var templateID uint16
	if v6 {
		templateID = t.templateIDv6
		err := setEntities(record, t.enrichEnterpriseID, &t.entitiesV6)
		if err != nil {
			return err
		}
	} else {
		templateID = t.templateIDv4
		err := setEntities(record, t.enrichEnterpriseID, &t.entitiesV4)
		if err != nil {
			return err
		}
	}
	err := dataSet.PrepareSet(entities.Data, templateID)
	if err != nil {
		return err
	}
	if v6 {
		err = dataSet.AddRecord(t.entitiesV6, templateID)
		if err != nil {
			return err
		}
	} else {
		err = dataSet.AddRecord(t.entitiesV4, templateID)
		if err != nil {
			return err
		}
	}
	_, err = t.exporter.SendSet(dataSet)
	if err != nil {
		return err
	}
	return nil
}

// Write writes a flow before being stored
func (t *writeIpfix) Write(entry config.GenericMap) {
	ilog.Tracef("entering writeIpfix Write")
	if IPv6Type == entry["Etype"].(uint32) {
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
	ilog.Debugf("entering NewWriteIpfix")

	ipfixConfigIn := api.WriteIpfix{}
	if params.Write != nil && params.Write.Ipfix != nil {
		ipfixConfigIn = *params.Write.Ipfix
	}
	// need to combine defaults with parameters that are provided in the config yaml file
	ipfixConfigIn.SetDefaults()

	if err := ipfixConfigIn.Validate(); err != nil {
		return nil, fmt.Errorf("the provided config is not valid: %w", err)
	}
	writeIpfix := &writeIpfix{}
	if params.Write != nil && params.Write.Ipfix != nil {
		writeIpfix.transport = params.Write.Ipfix.Transport
		writeIpfix.hostPort = fmt.Sprintf("%s:%d", params.Write.Ipfix.TargetHost, params.Write.Ipfix.TargetPort)
		writeIpfix.enrichEnterpriseID = uint32(params.Write.Ipfix.EnterpriseID)
	}
	// Initialize IPFIX registry and send templates
	registry.LoadRegistry()
	var err error
	if params.Write != nil && params.Write.Ipfix != nil && params.Write.Ipfix.EnterpriseID != 0 {
		err = loadCustomRegistry(writeIpfix.enrichEnterpriseID)
		if err != nil {
			ilog.Fatalf("Failed to load Custom(%d) Registry", writeIpfix.enrichEnterpriseID)
		}
	}

	// Create exporter using local server info
	input := ipfixExporter.ExporterInput{
		CollectorAddress:    writeIpfix.hostPort,
		CollectorProtocol:   writeIpfix.transport,
		ObservationDomainID: 1,
		TempRefTimeout:      1,
	}
	writeIpfix.exporter, err = ipfixExporter.InitExportingProcess(input)
	if err != nil {
		ilog.Fatalf("Got error when connecting to server %s: %v", writeIpfix.hostPort, err)
		return nil, err
	}
	ilog.Infof("Created exporter connecting to server with address: %s", writeIpfix.hostPort)

	writeIpfix.templateIDv4, writeIpfix.entitiesV4, err = SendTemplateRecordv4(writeIpfix.exporter, writeIpfix.enrichEnterpriseID)
	if err != nil {
		ilog.WithError(err).Error("Failed in send IPFIX template v4 record")
		return nil, err
	}

	writeIpfix.templateIDv6, writeIpfix.entitiesV6, err = SendTemplateRecordv6(writeIpfix.exporter, writeIpfix.enrichEnterpriseID)
	if err != nil {
		ilog.WithError(err).Error("Failed in send IPFIX template v6 record")
		return nil, err
	}
	return writeIpfix, nil
}
