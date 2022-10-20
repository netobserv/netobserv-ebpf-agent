package exporter

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/sirupsen/logrus"
	"github.com/vmware/go-ipfix/pkg/entities"
	ipfixExporter "github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var ilog = logrus.WithField("component", "exporter/IPFIXProto")

type IPFIXProto struct {
	hostPort     string
	exporter     *ipfixExporter.ExportingProcess
	templateIDv4 uint16
	templateIDv6 uint16
}

func addElementToTemplate(log *logrus.Entry, elementName string, value []byte, elements *[]entities.InfoElementWithValue) error {
	element, err := registry.GetInfoElement(elementName, registry.IANAEnterpriseID)
	if err != nil {
		log.WithError(err).Errorf("Did not find the element with name %s", elementName)
		return err
	}
	ie, err := entities.DecodeAndCreateInfoElementWithValue(element, value)
	if err != nil {
		log.WithError(err).Errorf("Failed to decode element %s", elementName)
		return err
	}
	*elements = append(*elements, ie)
	return nil
}

func makeByteFromUint8(value uint8) []byte {
	bs := make([]byte, 1)
	bs[0] = value
	return bs
}

func makeByteFromUint16(value uint16) []byte {
	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, value)
	return bs
}

func makeByteFromUint32(value uint32) []byte {
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, value)
	return bs
}

func makeByteFromUint64(value uint64) []byte {
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, value)
	return bs
}

// Flow Record to corresponding IPFIX Types
// EthProtocol -> ethernetType
// Direction   -> flowDirection
// SrcMac      -> sourceMacAddress
// DstMac      -> destinationMacAddress
// SrcAddr(v4) -> sourceIPv4Address
// DstAddr(v4) -> destinationIPv4Address
// SrcAddr(v6) -> sourceIPv6Address
// DstAddr(v6) -> destinationIPv6Address
// Protocol    -> protocolIdentifier/nextHeaderIPv6
// SrcPort     -> sourceTransportPort
// DstPort     -> destinationTransportPort
// Bytes       -> octetDeltaCount
// TimeFlowStart -> flowStartSeconds, flowStartNanoseconds
// TimeFlowEnd -> flowEndSeconds, flowEndNanoseconds
// Packets     -> packetDeltaCount
// Interface   -> interfaceName

func sendDataRecordv6(log *logrus.Entry, record *flow.Record, exporter *ipfixExporter.ExportingProcess, templateID uint16) error {
	dataSet := entities.NewSet(false)
	err := dataSet.PrepareSet(entities.Data, templateID)
	if err != nil {
		log.Errorf("Failed in PrepareSet")
		return err
	}
	elements := make([]entities.InfoElementWithValue, 0)

	err = addElementToTemplate(log, "ethernetType", makeByteFromUint16(record.EthProtocol), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "flowDirection", makeByteFromUint8(record.Direction), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "sourceMacAddress", net.HardwareAddr(record.DataLink.SrcMac[:]), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "destinationMacAddress", net.HardwareAddr(record.DataLink.DstMac[:]), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "sourceIPv6Address", record.Network.SrcAddr.IP(), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "destinationIPv6Address", record.Network.DstAddr.IP(), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "nextHeaderIPv6", makeByteFromUint8(record.Transport.Protocol), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "sourceTransportPort", makeByteFromUint16(record.Transport.SrcPort), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "destinationTransportPort", makeByteFromUint16(record.Transport.DstPort), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "octetDeltaCount", makeByteFromUint64(record.Bytes), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "flowStartSeconds", makeByteFromUint32(uint32(record.TimeFlowStart.Unix())), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "flowStartMilliseconds", makeByteFromUint64(uint64(record.TimeFlowStart.UnixMilli())), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "flowEndSeconds", makeByteFromUint32(uint32(record.TimeFlowEnd.Unix())), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "flowEndMilliseconds", makeByteFromUint64(uint64(record.TimeFlowEnd.UnixMilli())), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "packetDeltaCount", makeByteFromUint64(uint64(record.Packets)), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "interfaceName", []byte(record.Interface), &elements)
	if err != nil {
		return err
	}
	err = dataSet.AddRecord(elements, templateID)
	if err != nil {
		log.WithError(err).Error("Failed in Add Record")
		return err
	}
	_, err = exporter.SendSet(dataSet)
	if err != nil {
		log.WithError(err).Error("Failed in Send Record")
		return err
	}
	log.Printf("Sending IPFIX with %+v -> %+v", record.Network.SrcAddr.IP(), record.Network.DstAddr.IP())
	return nil
}

func sendDataRecordv4(log *logrus.Entry, record *flow.Record, exporter *ipfixExporter.ExportingProcess, templateID uint16) error {
	// Create data set with 1 data record
	dataSet := entities.NewSet(false)
	err := dataSet.PrepareSet(entities.Data, templateID)
	if err != nil {
		log.Errorf("Failed in PrepareSet")
		return err
	}
	elements := make([]entities.InfoElementWithValue, 0)

	err = addElementToTemplate(log, "ethernetType", makeByteFromUint16(record.EthProtocol), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "flowDirection", makeByteFromUint8(record.Direction), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "sourceMacAddress", net.HardwareAddr(record.DataLink.SrcMac[:]), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "destinationMacAddress", net.HardwareAddr(record.DataLink.DstMac[:]), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "sourceIPv4Address", record.Network.SrcAddr.IP().To4(), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "destinationIPv4Address", record.Network.DstAddr.IP().To4(), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "protocolIdentifier", makeByteFromUint8(record.Transport.Protocol), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "sourceTransportPort", makeByteFromUint16(record.Transport.SrcPort), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "destinationTransportPort", makeByteFromUint16(record.Transport.DstPort), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "octetDeltaCount", makeByteFromUint64(record.Bytes), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "flowStartSeconds", makeByteFromUint32(uint32(record.TimeFlowStart.Unix())), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "flowStartMilliseconds", makeByteFromUint64(uint64(record.TimeFlowStart.UnixMilli())), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "flowEndSeconds", makeByteFromUint32(uint32(record.TimeFlowEnd.Unix())), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "flowEndMilliseconds", makeByteFromUint64(uint64(record.TimeFlowEnd.UnixMilli())), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "packetDeltaCount", makeByteFromUint64(uint64(record.Packets)), &elements)
	if err != nil {
		return err
	}
	err = addElementToTemplate(log, "interfaceName", []byte(record.Interface), &elements)
	if err != nil {
		return err
	}
	err = dataSet.AddRecord(elements, templateID)
	if err != nil {
		log.WithError(err).Error("Failed in Add Record")
		return err
	}
	_, err = exporter.SendSet(dataSet)
	if err != nil {
		log.WithError(err).Error("Failed in Send Record")
		return err
	}
	log.Printf("Sending IPFIX with %+v -> %+v", record.Network.SrcAddr.IP(), record.Network.DstAddr.IP())
	return nil
}

func SendTemplateRecordv4(log *logrus.Entry, exporter *ipfixExporter.ExportingProcess) (uint16, error) {
	templateID := exporter.NewTemplateID()
	templateSet := entities.NewSet(false)
	err := templateSet.PrepareSet(entities.Template, templateID)
	if err != nil {
		log.WithError(err).Error("Failed in PrepareSet")
		return 0, err
	}
	elements := make([]entities.InfoElementWithValue, 0)

	err = addElementToTemplate(log, "ethernetType", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "flowDirection", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "sourceMacAddress", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "destinationMacAddress", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "sourceIPv4Address", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "destinationIPv4Address", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "protocolIdentifier", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "sourceTransportPort", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "destinationTransportPort", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "octetDeltaCount", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "flowStartSeconds", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "flowStartMilliseconds", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "flowEndSeconds", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "flowEndMilliseconds", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "packetDeltaCount", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "interfaceName", nil, &elements)
	if err != nil {
		return 0, err
	}

	fmt.Printf("%+v", elements)
	err = templateSet.AddRecord(elements, templateID)
	if err != nil {
		log.WithError(err).Error("Failed in Add Record")
		return 0, err
	}
	_, err = exporter.SendSet(templateSet)
	if err != nil {
		log.WithError(err).Error("Failed to send template record")
		return 0, err
	}

	return templateID, nil
}

func SendTemplateRecordv6(log *logrus.Entry, exporter *ipfixExporter.ExportingProcess) (uint16, error) {
	templateID := exporter.NewTemplateID()
	templateSet := entities.NewSet(false)
	err := templateSet.PrepareSet(entities.Template, templateID)
	if err != nil {
		log.WithError(err).Error("Failed in PrepareSet")
		return 0, err
	}
	elements := make([]entities.InfoElementWithValue, 0)

	err = addElementToTemplate(log, "ethernetType", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "flowDirection", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "sourceMacAddress", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "destinationMacAddress", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "sourceIPv6Address", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "destinationIPv6Address", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "nextHeaderIPv6", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "sourceTransportPort", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "destinationTransportPort", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "octetDeltaCount", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "flowStartSeconds", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "flowStartMilliseconds", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "flowEndSeconds", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "flowEndMilliseconds", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "packetDeltaCount", nil, &elements)
	if err != nil {
		return 0, err
	}
	err = addElementToTemplate(log, "interfaceName", nil, &elements)
	if err != nil {
		return 0, err
	}

	err = templateSet.AddRecord(elements, templateID)
	if err != nil {
		log.WithError(err).Error("Failed in Add Record")
		return 0, err
	}
	_, err = exporter.SendSet(templateSet)
	if err != nil {
		log.WithError(err).Error("Failed to send template record")
		return 0, err
	}

	return templateID, nil
}

// Sends out Template record to the IPFIX collector
func StartIPFIXProto(hostPort string, transportProto string) (*IPFIXProto, error) {
	log := ilog.WithField("collector", hostPort)

	registry.LoadRegistry()
	// Create exporter using local server info
	input := ipfixExporter.ExporterInput{
		CollectorAddress:    hostPort,
		CollectorProtocol:   transportProto,
		ObservationDomainID: 1,
		TempRefTimeout:      1,
	}
	exporter, err := ipfixExporter.InitExportingProcess(input)
	if err != nil {
		log.Fatalf("Got error when connecting to local server %s: %v", hostPort, err)
		return nil, err
	}
	log.Infof("Created exporter connecting to local server with address: %s", hostPort)

	templateIDv4, err := SendTemplateRecordv4(log, exporter)
	if err != nil {
		log.WithError(err).Error("Failed in send IPFIX template v4 record")
		return nil, err
	}

	templateIDv6, err := SendTemplateRecordv6(log, exporter)
	if err != nil {
		log.WithError(err).Error("Failed in send IPFIX template v6 record")
		return nil, err
	}
	return &IPFIXProto{
		hostPort:     hostPort,
		exporter:     exporter,
		templateIDv4: templateIDv4,
		templateIDv6: templateIDv6,
	}, nil
}

// TODO : Enable Support Function to close Connection
// func (ipf *IPFIXProto) StopExporter(input <-chan []*flow.Record) {
// 	ipf.exporter.CloseConnToCollector()
// }

// ExportFlows accepts slices of *flow.Record by its input channel, converts them
// to IPFIX Records, and submits them to the collector.
func (ipf *IPFIXProto) ExportFlows(input <-chan []*flow.Record) {
	log := ilog.WithField("collector", ipf.hostPort)
	for inputRecords := range input {
		for _, record := range inputRecords {
			if record.EthProtocol == flow.IPv6Type {
				err := sendDataRecordv6(log, record, ipf.exporter, ipf.templateIDv6)
				if err != nil {
					log.WithError(err).Error("Failed in send IPFIX data record")
				}
			} else {
				err := sendDataRecordv4(log, record, ipf.exporter, ipf.templateIDv4)
				if err != nil {
					log.WithError(err).Error("Failed in send IPFIX data record")
				}
			}
		}
	}
	ipf.exporter.CloseConnToCollector()
}
