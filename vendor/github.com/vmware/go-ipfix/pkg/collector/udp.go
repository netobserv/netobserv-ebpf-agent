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

	"github.com/pion/dtls/v2"
	"k8s.io/klog/v2"
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
		cp.wg.Add(1)
		go func() {
			defer cp.wg.Done()
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
				address, err = net.ResolveUDPAddr(conn.RemoteAddr().Network(), conn.RemoteAddr().String())
				if err != nil {
					klog.Errorf("Error in dtls collecting process: %v", err)
					return
				}
				klog.V(2).Infof("Receiving %d bytes from %s", size, address.String())
				buffBytes := make([]byte, size)
				copy(buffBytes, buff[0:size])
				cp.handleUDPMessage(address, buffBytes)
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
		cp.wg.Add(1)
		go func() {
			defer cp.wg.Done()
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
				cp.handleUDPMessage(address, buff[0:size])
			}
		}()
	}
	<-cp.stopChan
}

func (cp *CollectingProcess) handleUDPMessage(address net.Addr, buf []byte) {
	addr := address.String()
	session := func() *transportSession {
		cp.mutex.Lock()
		defer cp.mutex.Unlock()
		if session, ok := cp.sessions[addr]; ok {
			return session
		}
		return cp.createUDPClient(addr)
	}()
	// closeSessionChan is necessary to make sure that there is no possibility of deadlock when
	// the client goroutine decides that shutting down is necessary. Otherwise we could end up
	// in a situation where the client goroutine is no longer consuming messages, but this
	// goroutine is blocked on writing to packetChan. Therefore, when the client goroutine needs
	// to shutdown, it will also close closeSessionChan, to ensure that we don't block here.
	select {
	case session.packetChan <- bytes.NewBuffer(buf):
		break
	case <-session.closeSessionChan:
		break
	}
}

// createUDPClient is invoked with an exclusive lock on cp.mutex.
func (cp *CollectingProcess) createUDPClient(addr string) *transportSession {
	session := newUDPSession(addr)
	cp.sessions[addr] = session
	cp.wg.Add(1)
	go func() {
		defer cp.wg.Done()
		timer := cp.clock.NewTimer(cp.templateTTL)
		defer timer.Stop()
		defer close(session.closeSessionChan)
		defer func() {
			cp.mutex.Lock()
			defer cp.mutex.Unlock()
			delete(cp.sessions, addr)
		}()
		for {
			select {
			case <-cp.stopChan:
				klog.Infof("Collecting process from %s has stopped.", addr)
				return
			case <-timer.C(): // set timeout for udp connection
				klog.Errorf("UDP connection from %s timed out.", addr)
				return
			case packet := <-session.packetChan:
				// get the message here
				message, err := cp.decodePacket(session, packet, addr)
				if err != nil {
					klog.Error(err)
					// For UDP, there is no point in returning here, as the
					// client would not become aware that there is an issue.
					// This is why the template refresh mechanism exists.
					continue
				}
				klog.V(4).Infof("Processed message from exporter %v, number of records: %v, observation domain ID: %v",
					message.GetExportAddress(), message.GetSet().GetNumberOfRecords(), message.GetObsDomainID())
				timer.Reset(cp.templateTTL)
			}
		}
	}()
	return session
}
