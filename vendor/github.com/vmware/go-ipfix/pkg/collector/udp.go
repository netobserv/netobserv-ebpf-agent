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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/pion/dtls/v2"
	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/entities"
)

func (cp *CollectingProcess) startUDPServer() {
	var listener net.Listener
	var err error
	var conn net.Conn
	address, err := net.ResolveUDPAddr(cp.protocol, cp.address)
	if err != nil {
		klog.Error(err)
		return
	}
	if cp.isEncrypted { // use DTLS
		cert, err := tls.X509KeyPair(cp.serverCert, cp.serverKey)
		if err != nil {
			klog.Error(err)
			return
		}
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(cp.serverCert)
		config := &dtls.Config{
			Certificates:         []tls.Certificate{cert},
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
			ClientCAs:            certPool,
		}
		listener, err = dtls.Listen("udp", address, config)
		if err != nil {
			klog.Error(err)
			return
		}
		defer listener.Close()
		cp.updateAddress(listener.Addr())
		klog.Infof("Start dtls collecting process on %s", cp.netAddress)
		conn, err = listener.Accept()
		if err != nil {
			klog.Error(err)
			return
		}
		defer conn.Close()
		go func() {
			buff := make([]byte, cp.maxBufferSize)
			for {
				size, err := conn.Read(buff)
				if err != nil {
					if size == 0 { // received stop collector message
						return
					}
					klog.Errorf("Error in collecting process: %v", err)
					return
				}
				address, err = net.ResolveUDPAddr(conn.LocalAddr().Network(), conn.LocalAddr().String())
				if err != nil {
					klog.Errorf("Error in dtls collecting process: %v", err)
					return
				}
				klog.V(2).Infof("Receiving %d bytes from %s", size, address.String())
				cp.handleUDPClient(address)
				buffBytes := make([]byte, size)
				copy(buffBytes, buff[0:size])
				cp.clients[address.String()].packetChan <- bytes.NewBuffer(buffBytes)
			}
		}()
	} else { // use udp
		conn, err := net.ListenUDP("udp", address)
		if err != nil {
			klog.Error(err)
			return
		}
		cp.updateAddress(conn.LocalAddr())
		klog.Infof("Start UDP collecting process on %s", cp.netAddress)
		defer conn.Close()
		go func() {
			for {
				buff := make([]byte, cp.maxBufferSize)
				size, address, err := conn.ReadFromUDP(buff)
				if err != nil {
					if size == 0 { // received stop collector message
						return
					}
					klog.Errorf("Error in udp collecting process: %v", err)
					return
				}
				klog.V(2).Infof("Receiving %d bytes from %s", size, address.String())
				cp.handleUDPClient(address)
				cp.clients[address.String()].packetChan <- bytes.NewBuffer(buff[0:size])
			}
		}()
	}
	<-cp.stopChan
}

func (cp *CollectingProcess) handleUDPClient(address net.Addr) {
	if _, exist := cp.clients[address.String()]; !exist {
		client := cp.createClient()
		cp.addClient(address.String(), client)
		cp.wg.Add(1)
		go func() {
			defer cp.wg.Done()
			ticker := time.NewTicker(time.Duration(entities.TemplateRefreshTimeOut) * time.Second)
			for {
				select {
				case <-cp.stopChan:
					klog.Infof("Collecting process from %s has stopped.", address.String())
					cp.deleteClient(address.String())
					return
				case <-ticker.C: // set timeout for udp connection
					klog.Errorf("UDP connection from %s timed out.", address.String())
					cp.deleteClient(address.String())
					return
				case packet := <-client.packetChan:
					// get the message here
					message, err := cp.decodePacket(packet, address.String())
					if err != nil {
						klog.Error(err)
						return
					}
					klog.V(4).Infof("Processed message from exporter %v, number of records: %v, observation domain ID: %v",
						message.GetExportAddress(), message.GetSet().GetNumberOfRecords(), message.GetObsDomainID())
					ticker.Stop()
					ticker = time.NewTicker(time.Duration(entities.TemplateRefreshTimeOut) * time.Second)
				}
			}
		}()
	}
}
