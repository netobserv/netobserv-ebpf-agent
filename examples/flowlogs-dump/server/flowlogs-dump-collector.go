/*
 * Copyright (C) 2022 IBM, Inc.
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

package main

import (
	"flag"
	"log"
	"net"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/grpc"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
)

const ipv6 = 0x86DD

var (
	port = flag.Int("listen_port", 9999, "TCP port to listen for flows")
)

var protocolByNumber = map[uint32]string{
	1:  "icmp",
	2:  "igmp",
	6:  "tcp",
	17: "udp",
	58: "ipv6-icmp",
}

var ipProto = map[uint32]string{
	0x0800: "ipv4",
	0x0806: "arp",
	0x86DD: "ipv6",
}

func ipIntToNetIP(ipAsInt uint32) net.IP {
	var bytes [4]byte
	bytes[0] = byte(ipAsInt & 0xFF)
	bytes[1] = byte((ipAsInt >> 8) & 0xFF)
	bytes[2] = byte((ipAsInt >> 16) & 0xFF)
	bytes[3] = byte((ipAsInt >> 24) & 0xFF)

	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0])
}

// tcpdump flow collector
func main() {
	log.SetFlags(0)
	flag.Parse()

	receivedRecords := make(chan *pbflow.Records, 1000)
	log.Println("starting flowlogs-dump-collector on port", *port)
	go func() {
		_, err := grpc.StartCollector(*port, receivedRecords)
		if err != nil {
			panic(err)
		}
	}()
	for records := range receivedRecords {
		for _, record := range records.Entries {
			if record.EthProtocol == ipv6 {
				log.Printf("%s: %v %s IP %s:%d > %s:%d: protocol:%s type: %d code: %d dir:%d bytes:%d packets:%d flags:%d ends: %v dnsId: %d dnsFlags: 0x%04x dnsReq: %v dnsRsp: %v\n",
					ipProto[record.EthProtocol],
					record.TimeFlowStart.AsTime().Local().Format("15:04:05.000000"),
					record.Interface,
					net.IP(record.Network.GetSrcAddr().GetIpv6()).To16(),
					record.Transport.SrcPort,
					net.IP(record.Network.GetDstAddr().GetIpv6()).To16(),
					record.Transport.DstPort,
					protocolByNumber[record.Transport.Protocol],
					record.IcmpType,
					record.IcmpCode,
					record.Direction,
					record.Bytes,
					record.Packets,
					record.Flags,
					record.TimeFlowEnd.AsTime().Local().Format("15:04:05.000000"),
					record.GetDnsId(),
					record.GetDnsFlags(),
					record.GetTimeDnsReq(),
					record.GetTimeDnsRsp(),
				)
			} else {
				log.Printf("%s: %v %s IP %s:%d > %s:%d: protocol:%s type: %d code: %d dir:%d bytes:%d packets:%d flags:%d ends: %v dnsId: %d dnsFlags: 0x%04x dnsReq: %v dnsRsp: %v\n",
					ipProto[record.EthProtocol],
					record.TimeFlowStart.AsTime().Local().Format("15:04:05.000000"),
					record.Interface,
					ipIntToNetIP(record.Network.GetSrcAddr().GetIpv4()).String(),
					record.Transport.SrcPort,
					ipIntToNetIP(record.Network.GetDstAddr().GetIpv4()).String(),
					record.Transport.DstPort,
					protocolByNumber[record.Transport.Protocol],
					record.IcmpType,
					record.IcmpCode,
					record.Direction,
					record.Bytes,
					record.Packets,
					record.Flags,
					record.TimeFlowEnd.AsTime().Local().Format("15:04:05.000000"),
					record.GetDnsId(),
					record.GetDnsFlags(),
					record.GetTimeDnsReq(),
					record.GetTimeDnsRsp(),
				)
			}
		}
	}
}
