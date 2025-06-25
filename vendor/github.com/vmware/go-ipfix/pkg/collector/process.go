// Copyright 2020 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

// DecodingMode specifies how unknown information elements (in templates) are handled when decoding.
// Unknown information elements are elements which are not part of the static registry included with
// the library.
// Note that regardless of the DecodingMode, data sets must always match the corresponding template.
type DecodingMode string

const (
	// DecodingModeStrict will cause decoding to fail when an unknown IE is encountered in a template.
	DecodingModeStrict DecodingMode = "Strict"
	// DecodingModeLenientKeepUnknown will accept unknown IEs in templates. When decoding the
	// corresponding field in a data record, the value will be preserved (as an octet array).
	DecodingModeLenientKeepUnknown DecodingMode = "LenientKeepUnknown"
	// DecodingModeLenientDropUnknown will accept unknown IEs in templates. When decoding the
	// corresponding field in a data record, the value will be dropped (information element will
	// not be present in the resulting Record). Be careful when using this mode as the IEs
	// included in the resulting Record will no longer match the received template.
	DecodingModeLenientDropUnknown DecodingMode = "LenientDropUnknown"
)

type template struct {
	ies         []*entities.InfoElement
	expiryTime  time.Time
	expiryTimer timer
}

type CollectingProcess struct {
	// mutex allows multiple readers or one writer at the same time
	mutex sync.RWMutex
	// template lifetime
	templateTTL time.Duration
	// server information
	address string
	// server protocol
	protocol string
	// server net address
	netAddress net.Addr
	// maximum buffer size to read the record
	maxBufferSize uint16
	// chanel to receive stop information
	stopChan chan struct{}
	// messageChan is the channel to output message
	messageChan chan *entities.Message
	// a map of all transport sessions (clients) identified by the remote client address
	sessions map[string]*transportSession
	// isEncrypted indicates whether to use TLS/DTLS for communication
	isEncrypted bool
	// numExtraElements specifies number of elements that could be added after
	// decoding the IPFIX data packet.
	numExtraElements int
	// decodingMode specifies how unknown information elements (in templates) are handled when
	// decoding.
	decodingMode DecodingMode
	// caCert, serverCert and serverKey are for storing encryption info when using TLS/DTLS
	caCert          []byte
	serverCert      []byte
	serverKey       []byte
	tlsCipherSuites []uint16
	tlsMinVersion   uint16
	wg              sync.WaitGroup
	// stats for IPFIX objects received
	numOfMessagesReceived        uint64
	numOfTemplateSetsReceived    uint64
	numOfDataSetsReceived        uint64
	numOfTemplateRecordsReceived uint64
	numOfDataRecordsReceived     uint64
	// clock implementation: enables injecting a fake clock for testing
	clock clock
}

type CollectorInput struct {
	IsIPv6      bool
	IsEncrypted bool
	// Address needs to be provided in hostIP:port format.
	Address string
	// Protocol needs to be provided in lower case format.
	// We support "tcp" and "udp" protocols.
	Protocol      string
	MaxBufferSize uint16
	TemplateTTL   uint32
	// TODO: group following fields into struct to be reuse in exporter
	CACert     []byte
	ServerCert []byte
	ServerKey  []byte
	// List of supported cipher suites.
	// From https://pkg.go.dev/crypto/tls#pkg-constants
	// The order of the list is ignored.Note that TLS 1.3 ciphersuites are not configurable.
	// For DTLS, cipher suites are from https://pkg.go.dev/github.com/pion/dtls/v2@v2.2.12/internal/ciphersuite#ID.
	TLSCipherSuites []uint16
	// Min TLS version.
	// From https://pkg.go.dev/crypto/tls#pkg-constants
	// Not configurable for DTLS, as only DTLS 1.2 is supported.
	TLSMinVersion    uint16
	NumExtraElements int
	// DecodingMode specifies how unknown information elements (in templates) are handled when
	// decoding. The default value is DecodingModeStrict for historical reasons. For most uses,
	// DecodingModeLenientKeepUnknown is the most appropriate mode.
	DecodingMode DecodingMode
}

func initCollectingProcess(input CollectorInput, clock clock) (*CollectingProcess, error) {
	templateTTLSeconds := input.TemplateTTL
	if input.Protocol == "udp" && templateTTLSeconds == 0 {
		templateTTLSeconds = entities.TemplateTTL
	}
	templateTTL := time.Duration(templateTTLSeconds) * time.Second
	decodingMode := input.DecodingMode
	if decodingMode == "" {
		decodingMode = DecodingModeStrict
	}
	klog.InfoS(
		"Initializing the collecting process",
		"encrypted", input.IsEncrypted, "address", input.Address, "protocol", input.Protocol, "maxBufferSize", input.MaxBufferSize,
		"templateTTL", templateTTL, "numExtraElements", input.NumExtraElements, "decodingMode", decodingMode,
	)
	cp := &CollectingProcess{
		mutex:            sync.RWMutex{},
		templateTTL:      templateTTL,
		address:          input.Address,
		protocol:         input.Protocol,
		maxBufferSize:    input.MaxBufferSize,
		stopChan:         make(chan struct{}),
		messageChan:      make(chan *entities.Message),
		sessions:         make(map[string]*transportSession),
		isEncrypted:      input.IsEncrypted,
		caCert:           input.CACert,
		serverCert:       input.ServerCert,
		serverKey:        input.ServerKey,
		tlsCipherSuites:  input.TLSCipherSuites,
		tlsMinVersion:    input.TLSMinVersion,
		numExtraElements: input.NumExtraElements,
		decodingMode:     decodingMode,
		clock:            clock,
	}
	return cp, nil
}

func InitCollectingProcess(input CollectorInput) (*CollectingProcess, error) {
	return initCollectingProcess(input, realClock{})
}

func (cp *CollectingProcess) Start() {
	klog.Info("Starting the collecting process")
	switch cp.protocol {
	case "tcp":
		cp.startTCPServer()
	case "udp":
		cp.startUDPServer()
	}
}

func (cp *CollectingProcess) Stop() {
	close(cp.stopChan)
	// wait for all connections to be safely deleted and returned
	cp.wg.Wait()
	// the message channel can only be closed AFTER all goroutines have returned
	close(cp.messageChan)
	klog.Info("Stopped the collecting process")
}

func (cp *CollectingProcess) GetAddress() net.Addr {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	return cp.netAddress
}

func (cp *CollectingProcess) GetMsgChan() <-chan *entities.Message {
	return cp.messageChan
}

// GetNumRecordsReceived returns the number of data records received by the collector.
func (cp *CollectingProcess) GetNumRecordsReceived() int64 {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	return int64(cp.numOfDataRecordsReceived)
}

// GetNumMessagesReceived returns the number of IPFIX messages received by the collector.
func (cp *CollectingProcess) GetNumMessagesReceived() int64 {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	return int64(cp.numOfMessagesReceived)
}

func (cp *CollectingProcess) GetNumConnToCollector() int64 {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	return int64(len(cp.sessions))
}

func (cp *CollectingProcess) incrementReceivedStats(numMessages, numTemplateSets, numDataSets, numTemplateRecords, numDataRecords uint64) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	cp.numOfMessagesReceived += numMessages
	cp.numOfTemplateSetsReceived += numTemplateSets
	cp.numOfDataSetsReceived += numDataSets
	cp.numOfTemplateRecordsReceived += numTemplateRecords
	cp.numOfDataRecordsReceived += numDataRecords
}

func decodeMessageHeader(buf *bytes.Buffer, version *uint16, length *uint16, exportTime *uint32, sequenceNum *uint32, obsDomainID *uint32) error {
	data := buf.Next(entities.MsgHeaderLength)
	if len(data) < entities.MsgHeaderLength {
		return fmt.Errorf("buffer too short")
	}
	bigEndian := binary.BigEndian
	*version = bigEndian.Uint16(data)
	*length = bigEndian.Uint16(data[2:])
	*exportTime = bigEndian.Uint32(data[4:])
	*sequenceNum = bigEndian.Uint32(data[8:])
	*obsDomainID = bigEndian.Uint32(data[12:])
	return nil
}

func decodeSetHeader(buf *bytes.Buffer, setID, setLen *uint16) error {
	data := buf.Next(entities.SetHeaderLen)
	if len(data) < entities.SetHeaderLen {
		return fmt.Errorf("buffer too short")
	}
	bigEndian := binary.BigEndian
	*setID = bigEndian.Uint16(data)
	*setLen = bigEndian.Uint16(data[2:])
	return nil
}

func (cp *CollectingProcess) decodePacket(session *transportSession, packetBuffer *bytes.Buffer, exportAddress string) (*entities.Message, error) {
	var length, version, setID, setLen uint16
	var exportTime, sequenceNum, obsDomainID uint32
	if err := decodeMessageHeader(packetBuffer, &version, &length, &exportTime, &sequenceNum, &obsDomainID); err != nil {
		return nil, fmt.Errorf("failed to decode IPFIX message header: %w", err)
	}
	if version != uint16(10) {
		return nil, fmt.Errorf("collector only supports IPFIX (v10); invalid version %d received", version)
	}

	message := entities.NewMessage(true)
	message.SetVersion(version)
	message.SetMessageLen(length)
	message.SetExportTime(exportTime)
	message.SetSequenceNum(sequenceNum)
	message.SetObsDomainID(obsDomainID)

	// handle IPv6 address which may involve []
	portIndex := strings.LastIndex(exportAddress, ":")
	exportAddress = exportAddress[:portIndex]
	exportAddress = strings.ReplaceAll(exportAddress, "[", "")
	exportAddress = strings.ReplaceAll(exportAddress, "]", "")
	message.SetExportAddress(exportAddress)

	// At the moment we assume exactly one set per IPFIX message.
	if packetBuffer.Len() == 0 {
		return nil, fmt.Errorf("empty IPFIX message")
	}
	if err := decodeSetHeader(packetBuffer, &setID, &setLen); err != nil {
		return nil, fmt.Errorf("failed to decode set header: %w", err)
	}

	var numTemplateSets, numDataSets, numTemplateRecords, numDataRecords uint64

	var set entities.Set
	var err error
	if setID == entities.TemplateSetID {
		set, err = cp.decodeTemplateSet(session, packetBuffer, obsDomainID)
		if err != nil {
			return nil, fmt.Errorf("error in decoding message: %v", err)
		}
		numTemplateSets += 1
		numTemplateRecords += uint64(set.GetNumberOfRecords())
	} else {
		set, err = cp.decodeDataSet(session, packetBuffer, obsDomainID, setID)
		if err != nil {
			return nil, fmt.Errorf("error in decoding message: %v", err)
		}
		numDataSets += 1
		numDataRecords += uint64(set.GetNumberOfRecords())
	}
	message.AddSet(set)

	cp.incrementReceivedStats(1, numTemplateSets, numDataSets, numTemplateRecords, numDataRecords)

	// the thread(s)/client(s) executing the code will get blocked until the message is consumed/read in other goroutines.
	cp.messageChan <- message
	return message, nil
}

func decodeTemplateRecordHeader(buf *bytes.Buffer, templateID, fieldCount *uint16) error {
	data := buf.Next(entities.TemplateRecordHeaderLength)
	if len(data) < entities.TemplateRecordHeaderLength {
		return fmt.Errorf("buffer too short")
	}
	bigEndian := binary.BigEndian
	*templateID = bigEndian.Uint16(data)
	*fieldCount = bigEndian.Uint16(data[2:])
	return nil
}

func decodeTemplateRecordField(buf *bytes.Buffer, elementID, elementLength *uint16, enterpriseID *uint32) error {
	data := buf.Next(4)
	if len(data) < 4 {
		return fmt.Errorf("buffer too short")
	}
	bigEndian := binary.BigEndian
	*elementID = bigEndian.Uint16(data)
	*elementLength = bigEndian.Uint16(data[2:])
	// check whether enterprise ID is 0 or not
	isNonIANARegistry := (*elementID & 0x8000) > 0
	if isNonIANARegistry {
		/*
			Encoding format for Enterprise-Specific Information Elements:
			 0                   1                   2                   3
			 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|1| Information element id. = 15 | Field Length = 4  (16 bits)  |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			| Enterprise number (32 bits)                                   |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			1: 1 bit
			Information element id: 15 bits
			Field Length: 16 bits
			Enterprise ID: 32 bits
			(Reference: https://tools.ietf.org/html/rfc7011#appendix-A.2.2)
		*/
		data = buf.Next(4)
		if len(data) < 4 {
			return fmt.Errorf("buffer too short")
		}
		*enterpriseID = bigEndian.Uint32(data)
		// clear enterprise bit
		*elementID &= 0x7fff
	} else {
		*enterpriseID = registry.IANAEnterpriseID
	}
	return nil
}

func (cp *CollectingProcess) decodeTemplateSet(session *transportSession, templateBuffer *bytes.Buffer, obsDomainID uint32) (entities.Set, error) {
	// At the moment we assume exactly one record per template set.
	var templateID uint16
	var fieldCount uint16
	if err := decodeTemplateRecordHeader(templateBuffer, &templateID, &fieldCount); err != nil {
		return nil, fmt.Errorf("failed to decode template record header: %w", err)
	}

	decodeField := func() (entities.InfoElementWithValue, error) {
		var element *entities.InfoElement
		var elementID uint16
		var elementLength uint16
		var enterpriseID uint32
		if err := decodeTemplateRecordField(templateBuffer, &elementID, &elementLength, &enterpriseID); err != nil {
			return nil, fmt.Errorf("failed to decode template record field: %w", err)
		}
		var err error
		if enterpriseID == registry.IANAEnterpriseID {
			element, err = registry.GetInfoElementFromID(elementID, enterpriseID)
			if err != nil {
				if cp.decodingMode == DecodingModeStrict {
					return nil, err
				}
				klog.InfoS("Template includes an information element that is not present in registry", "obsDomainID", obsDomainID, "templateID", templateID, "enterpriseID", enterpriseID, "elementID", elementID)
				element = entities.NewInfoElement("", elementID, entities.OctetArray, enterpriseID, elementLength)
			}
		} else {
			element, err = registry.GetInfoElementFromID(elementID, enterpriseID)
			if err != nil {
				if cp.decodingMode == DecodingModeStrict {
					return nil, err
				}
				klog.InfoS("Template includes an information element that is not present in registry", "obsDomainID", obsDomainID, "templateID", templateID, "enterpriseID", enterpriseID, "elementID", elementID)
				element = entities.NewInfoElement("", elementID, entities.OctetArray, enterpriseID, elementLength)
			}
		}

		return entities.DecodeAndCreateInfoElementWithValue(element, nil)
	}

	elementsWithValue, err := func() ([]entities.InfoElementWithValue, error) {
		elementsWithValue := make([]entities.InfoElementWithValue, int(fieldCount))
		for i := range fieldCount {
			elementWithValue, err := decodeField()
			if err != nil {
				return nil, err
			}
			elementsWithValue[i] = elementWithValue
		}
		return elementsWithValue, nil
	}()
	if err != nil {
		// Delete existing template (if one exists) from template map if the new one is invalid.
		// This is particularly useful for UDP collection, as there is no feedback mechanism
		// to let the sender know that the new template is invalid (while with TCP, we can close
		// the connection). If we keep the old template and the sender sends data records
		// which use the new template, we would try to decode them according to the old
		// template, which would cause issues.
		session.deleteTemplate(obsDomainID, templateID)
		return nil, err
	}

	templateSet := entities.NewSet(true)
	if err := templateSet.PrepareSet(entities.Template, templateID); err != nil {
		return nil, err
	}
	if err := templateSet.AddRecordV2(elementsWithValue, templateID); err != nil {
		return nil, err
	}
	session.addTemplate(cp.clock, obsDomainID, templateID, elementsWithValue, cp.templateTTL)
	return templateSet, nil
}

func (cp *CollectingProcess) decodeDataSet(session *transportSession, dataBuffer *bytes.Buffer, obsDomainID uint32, templateID uint16) (entities.Set, error) {
	// make sure template exists
	template, err := session.getTemplateIEs(obsDomainID, templateID)
	if err != nil {
		return nil, fmt.Errorf("template %d with obsDomainID %d does not exist", templateID, obsDomainID)
	}
	dataSet := entities.NewSet(true)
	if err = dataSet.PrepareSet(entities.Data, templateID); err != nil {
		return nil, err
	}

	for dataBuffer.Len() > 0 {
		elements := make([]entities.InfoElementWithValue, 0, len(template)+cp.numExtraElements)
		for _, ie := range template {
			var length int
			if ie.Len == entities.VariableLength { // string / octet array
				var err error
				length, err = getFieldLength(dataBuffer)
				if err != nil {
					return nil, fmt.Errorf("failed to read variable field length: %w", err)
				}
			} else {
				length = int(ie.Len)
			}
			element, err := entities.DecodeAndCreateInfoElementWithValue(ie, dataBuffer.Next(length))
			if err != nil {
				return nil, err
			}
			// A missing name means an unknown element was received
			if cp.decodingMode == DecodingModeLenientDropUnknown && ie.Name == "" {
				klog.V(5).InfoS("Dropping field for unknown information element", "obsDomainID", obsDomainID, "ie", ie)
				continue
			}
			elements = append(elements, element)
		}
		err = dataSet.AddRecordV2(elements, templateID)
		if err != nil {
			return nil, err
		}
	}
	return dataSet, nil
}

func (cp *CollectingProcess) updateAddress(address net.Addr) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	cp.netAddress = address
}

// getMessageLength returns buffer length by decoding the header
func getMessageLength(reader *bufio.Reader) (int, error) {
	partialHeader, err := reader.Peek(4)
	if err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(partialHeader[2:])), nil
}

// getFieldLength returns string field length for data record
// (encoding reference: https://tools.ietf.org/html/rfc7011#appendix-A.5)
func getFieldLength(dataBuffer *bytes.Buffer) (int, error) {
	oneByte, err := dataBuffer.ReadByte()
	if err != nil {
		return 0, err
	}
	if oneByte < 255 { // string length is less than 255
		return int(oneByte), nil
	}
	twoBytes := dataBuffer.Next(2)
	if len(twoBytes) < 2 {
		return 0, fmt.Errorf("buffer too short")
	}
	return int(binary.BigEndian.Uint16(twoBytes)), nil
}
