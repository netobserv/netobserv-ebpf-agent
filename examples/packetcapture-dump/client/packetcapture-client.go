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
	"fmt"
	"os"
	"time"

	grpc "github.com/netobserv/netobserv-ebpf-agent/pkg/grpc/packet"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbpacket"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/utils/packets"

	"github.com/gopacket/gopacket/layers"
)

var (
	PORT     = flag.Int("port", 9990, "gRPC collector port for packet stream")
	FILENAME = flag.String("outfile", "", "Create and write to <Filename>.pcap")
)

// Setting Snapshot length to 0 sets it to maximum packet size
var snapshotlen uint32

func check(e error) {
	if e != nil {
		panic(e)
	}
}
func main() {
	fmt.Println("Starting Packet Capture Client.")
	fmt.Println("By default, the read packets are printed on stdout.")
	fmt.Println("To write to a pcap file use flag '-outfile=[filename]'")
	fmt.Println("This creates a file [filename] and writes packets to it.")

	fmt.Println("To view captured packets 'tcpdump -r [filename]'.")
	flag.Parse()

	flowPackets := make(chan *pbpacket.Packet, 100)
	collector, err := grpc.StartCollector(*PORT, flowPackets)
	if err != nil {
		fmt.Println("StartCollector failed:", err.Error())
		os.Exit(1)
	}

	var f *os.File
	if *FILENAME != "" {
		f, err = os.Create(*FILENAME)
		if err != nil {
			fmt.Println("Create file failed:", err.Error())
			os.Exit(1)
		}
		// write pcap file header
		_, err = f.Write(packets.GetPCAPFileHeader(snapshotlen, layers.LinkTypeEthernet))
		if err != nil {
			fmt.Println("Write file header failed:", err.Error())
			os.Exit(1)
		}
		fmt.Println("writting into", *FILENAME)

		defer f.Close()
		for fp := range flowPackets {
			_, err = f.Write(fp.Pcap.Value)
			check(err)
			dt := time.Now()
			fmt.Println(dt.Format("01-02-2006 15:04:05.000000"), ": Received Packet of length ", len(fp.Pcap.Value))
		}
	} else {
		fmt.Println("printing stdout without saving in file")

		for fp := range flowPackets {
			//nolint:staticcheck
			fmt.Println(fp.Pcap.Value)
		}
	}
	collector.Close()
}
