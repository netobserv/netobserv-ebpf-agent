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
	"github.com/vmware/go-ipfix/pkg/util"
)

type CollectingProcess struct {
	// for each obsDomainID, there is a map of templates
	templatesMap map[uint32]map[uint16][]*entities.InfoElement
	// mutex allows multiple readers or one writer at the same time
	mutex sync.RWMutex
	// template lifetime
	templateTTL uint32
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
	// maps each client to its client handler (required channels)
	clients map[string]*clientHandler
	// isEncrypted indicates whether to use TLS/DTLS for communication
	isEncrypted bool
	// numExtraElements specifies number of elements that could be added after
	// decoding the IPFIX data packet.
	numExtraElements int
	// caCert, serverCert and serverKey are for storing encryption info when using TLS/DTLS
	caCert               []byte
	serverCert           []byte
	serverKey            []byte
	wg                   sync.WaitGroup
	numOfRecordsReceived uint64
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
	CACert           []byte
	ServerCert       []byte
	ServerKey        []byte
	NumExtraElements int
}

type clientHandler struct {
	packetChan chan *bytes.Buffer
}

func InitCollectingProcess(input CollectorInput) (*CollectingProcess, error) {
	collectProc := &CollectingProcess{
		templatesMap:     make(map[uint32]map[uint16][]*entities.InfoElement),
		mutex:            sync.RWMutex{},
		templateTTL:      input.TemplateTTL,
		address:          input.Address,
		protocol:         input.Protocol,
		maxBufferSize:    input.MaxBufferSize,
		stopChan:         make(chan struct{}),
		messageChan:      make(chan *entities.Message),
		clients:          make(map[string]*clientHandler),
		isEncrypted:      input.IsEncrypted,
		caCert:           input.CACert,
		serverCert:       input.ServerCert,
		serverKey:        input.ServerKey,
		numExtraElements: input.NumExtraElements,
	}
	return collectProc, nil
}

func (cp *CollectingProcess) Start() {
	if cp.protocol == "tcp" {
		cp.startTCPServer()
	} else if cp.protocol == "udp" {
		cp.startUDPServer()
	}
}

func (cp *CollectingProcess) Stop() {
	close(cp.stopChan)
	// wait for all connections to be safely deleted and returned
	cp.wg.Wait()
	klog.Info("stopping the collecting process")
}

func (cp *CollectingProcess) GetAddress() net.Addr {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	return cp.netAddress
}

func (cp *CollectingProcess) GetMsgChan() chan *entities.Message {
	return cp.messageChan
}

func (cp *CollectingProcess) CloseMsgChan() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	close(cp.messageChan)
}

func (cp *CollectingProcess) GetNumRecordsReceived() int64 {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	return int64(cp.numOfRecordsReceived)
}

func (cp *CollectingProcess) GetNumConnToCollector() int64 {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	return int64(len(cp.clients))
}

func (cp *CollectingProcess) incrementNumRecordsReceived() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	cp.numOfRecordsReceived = cp.numOfRecordsReceived + 1
}

func (cp *CollectingProcess) createClient() *clientHandler {
	return &clientHandler{
		packetChan: make(chan *bytes.Buffer),
	}
}

func (cp *CollectingProcess) addClient(address string, client *clientHandler) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	cp.clients[address] = client
}

func (cp *CollectingProcess) deleteClient(name string) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	delete(cp.clients, name)
}

func (cp *CollectingProcess) decodePacket(packetBuffer *bytes.Buffer, exportAddress string) (*entities.Message, error) {
	var length, version, setID, setLen uint16
	var exportTime, sequencNum, obsDomainID uint32
	if err := util.Decode(packetBuffer, binary.BigEndian, &version, &length, &exportTime, &sequencNum, &obsDomainID, &setID, &setLen); err != nil {
		return nil, err
	}
	if version != uint16(10) {
		return nil, fmt.Errorf("collector only supports IPFIX (v10); invalid version %d received", version)
	}

	message := entities.NewMessage(true)
	message.SetVersion(version)
	message.SetMessageLen(length)
	message.SetExportTime(exportTime)
	message.SetSequenceNum(sequencNum)
	message.SetObsDomainID(obsDomainID)

	// handle IPv6 address which may involve []
	portIndex := strings.LastIndex(exportAddress, ":")
	exportAddress = exportAddress[:portIndex]
	exportAddress = strings.Replace(exportAddress, "[", "", -1)
	exportAddress = strings.Replace(exportAddress, "]", "", -1)
	message.SetExportAddress(exportAddress)

	var set entities.Set
	var err error
	if setID == entities.TemplateSetID {
		set, err = cp.decodeTemplateSet(packetBuffer, obsDomainID)
		if err != nil {
			return nil, fmt.Errorf("error in decoding message: %v", err)
		}
	} else {
		set, err = cp.decodeDataSet(packetBuffer, obsDomainID, setID)
		if err != nil {
			return nil, fmt.Errorf("error in decoding message: %v", err)
		}
	}
	message.AddSet(set)

	// the thread(s)/client(s) executing the code will get blocked until the message is consumed/read in other goroutines.
	cp.messageChan <- message
	cp.incrementNumRecordsReceived()
	return message, nil
}

func (cp *CollectingProcess) decodeTemplateSet(templateBuffer *bytes.Buffer, obsDomainID uint32) (entities.Set, error) {
	var templateID uint16
	var fieldCount uint16
	if err := util.Decode(templateBuffer, binary.BigEndian, &templateID, &fieldCount); err != nil {
		return nil, err
	}

	templateSet := entities.NewSet(true)
	if err := templateSet.PrepareSet(entities.Template, templateID); err != nil {
		return nil, err
	}
	elementsWithValue := make([]entities.InfoElementWithValue, int(fieldCount))
	for i := 0; i < int(fieldCount); i++ {
		var element *entities.InfoElement
		var enterpriseID uint32
		var elementID uint16
		// check whether enterprise ID is 0 or not
		elementid := make([]byte, 2)
		var elementLength uint16
		err := util.Decode(templateBuffer, binary.BigEndian, &elementid, &elementLength)
		if err != nil {
			return nil, err
		}
		isNonIANARegistry := elementid[0]>>7 == 1
		if !isNonIANARegistry {
			elementID = binary.BigEndian.Uint16(elementid)
			enterpriseID = registry.IANAEnterpriseID
			element, err = registry.GetInfoElementFromID(elementID, enterpriseID)
			if err != nil {
				return nil, err
			}
		} else {
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
			err = util.Decode(templateBuffer, binary.BigEndian, &enterpriseID)
			if err != nil {
				return nil, err
			}
			elementid[0] = elementid[0] ^ 0x80
			elementID = binary.BigEndian.Uint16(elementid)
			element, err = registry.GetInfoElementFromID(elementID, enterpriseID)
			if err != nil {
				return nil, err
			}
		}
		if elementsWithValue[i], err = entities.DecodeAndCreateInfoElementWithValue(element, nil); err != nil {
			return nil, err
		}
	}
	err := templateSet.AddRecordV2(elementsWithValue, templateID)
	if err != nil {
		return nil, err
	}
	cp.addTemplate(obsDomainID, templateID, elementsWithValue)
	return templateSet, nil
}

func (cp *CollectingProcess) decodeDataSet(dataBuffer *bytes.Buffer, obsDomainID uint32, templateID uint16) (entities.Set, error) {
	// make sure template exists
	template, err := cp.getTemplate(obsDomainID, templateID)
	if err != nil {
		return nil, fmt.Errorf("template %d with obsDomainID %d does not exist", templateID, obsDomainID)
	}
	dataSet := entities.NewSet(true)
	if err = dataSet.PrepareSet(entities.Data, templateID); err != nil {
		return nil, err
	}

	for dataBuffer.Len() > 0 {
		elements := make([]entities.InfoElementWithValue, len(template), len(template)+cp.numExtraElements)
		for i, element := range template {
			var length int
			if element.Len == entities.VariableLength { // string
				length = getFieldLength(dataBuffer)
			} else {
				length = int(element.Len)
			}
			if elements[i], err = entities.DecodeAndCreateInfoElementWithValue(element, dataBuffer.Next(length)); err != nil {
				return nil, err
			}
		}
		err = dataSet.AddRecordV2(elements, templateID)
		if err != nil {
			return nil, err
		}
	}
	return dataSet, nil
}

func (cp *CollectingProcess) addTemplate(obsDomainID uint32, templateID uint16, elementsWithValue []entities.InfoElementWithValue) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	if _, exists := cp.templatesMap[obsDomainID]; !exists {
		cp.templatesMap[obsDomainID] = make(map[uint16][]*entities.InfoElement)
	}
	elements := make([]*entities.InfoElement, 0)
	for _, elementWithValue := range elementsWithValue {
		elements = append(elements, elementWithValue.GetInfoElement())
	}
	cp.templatesMap[obsDomainID][templateID] = elements
	// template lifetime management
	if cp.protocol == "tcp" {
		return
	}

	// Handle udp template expiration
	if cp.templateTTL == 0 {
		cp.templateTTL = entities.TemplateTTL // Default value
	}
	go func() {
		ticker := time.NewTicker(time.Duration(cp.templateTTL) * time.Second)
		defer ticker.Stop()
		select {
		case <-ticker.C:
			klog.Infof("Template with id %d, and obsDomainID %d is expired.", templateID, obsDomainID)
			cp.deleteTemplate(obsDomainID, templateID)
			break
		}
	}()
}

func (cp *CollectingProcess) getTemplate(obsDomainID uint32, templateID uint16) ([]*entities.InfoElement, error) {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()
	if elements, exists := cp.templatesMap[obsDomainID][templateID]; exists {
		return elements, nil
	} else {
		return nil, fmt.Errorf("template %d with obsDomainID %d does not exist", templateID, obsDomainID)
	}
}

func (cp *CollectingProcess) deleteTemplate(obsDomainID uint32, templateID uint16) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	delete(cp.templatesMap[obsDomainID], templateID)
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
	var msgLen uint16
	err = util.Decode(bytes.NewBuffer(partialHeader[2:]), binary.BigEndian, &msgLen)
	if err != nil {
		return 0, fmt.Errorf("cannot decode message: %w", err)
	}
	return int(msgLen), nil
}

// getFieldLength returns string field length for data record
// (encoding reference: https://tools.ietf.org/html/rfc7011#appendix-A.5)
func getFieldLength(dataBuffer *bytes.Buffer) int {
	oneByte, _ := dataBuffer.ReadByte()
	if oneByte < 255 { // string length is less than 255
		return int(oneByte)
	}
	var lengthTwoBytes uint16
	util.Decode(dataBuffer, binary.BigEndian, &lengthTwoBytes)
	return int(lengthTwoBytes)
}
