package exporter

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"

	"github.com/sirupsen/logrus"
)

type PCAPStream struct {
	hostPort   string
	clientConn net.Conn
}

var tplog = logrus.WithField("component", "packet/TCPPackets")

// Setting Snapshot length to 0 sets it to maximum packet size
var snapshotlen uint32

// WritePacket writes the given packet data out to the file.
func writeTCPPacket(ci gopacket.CaptureInfo, data []byte, conn net.Conn) error {
	if ci.CaptureLength != len(data) {
		return fmt.Errorf("capture length %d does not match data length %d", ci.CaptureLength, len(data))
	}
	if ci.CaptureLength > ci.Length {
		return fmt.Errorf("invalid capture info %+v:  capture length > length", ci)
	}
	tplog.Debugf("Sending Packet to client. Length: %d", len(data))
	b, err := GetPacketHeader(ci)
	if err != nil {
		return fmt.Errorf("error writing packet header: %w", err)
	}
	// write 16 byte packet header
	_, err = conn.Write(b)
	if err != nil {
		tplog.Fatal(err)
		return err
	}
	// write data
	_, err = conn.Write(data)
	if err != nil {
		tplog.Fatal(err)
	}
	return err
}

// FIXME: Only after client connects to it, the agent starts collecting and sending packets.
// This behavior needs to be fixed.
func StartTCPPacketSend(hostPort string) (*PCAPStream, error) {
	PORT := ":" + hostPort
	l, err := net.Listen("tcp", PORT)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	clientConn, err := l.Accept()

	if err != nil {
		return nil, err
	}

	return &PCAPStream{
		hostPort:   hostPort,
		clientConn: clientConn,
	}, nil
}

func (p *PCAPStream) ExportTCPPackets(in <-chan []*flow.PacketRecord) {
	//Create handler by opening PCAP stream - Write 24 byte size PCAP File Header
	_, err := p.clientConn.Write(GetPCAPFileHeader(snapshotlen, layers.LinkTypeEthernet))
	if err != nil {
		tplog.Fatal(err)
	}
	for packetRecord := range in {
		if len(packetRecord) > 0 {
			for _, packet := range packetRecord {
				packetStream := packet.Stream
				packetTimestamp := packet.Time
				if len(packetStream) != 0 {
					captureInfo := gopacket.CaptureInfo{
						Timestamp:     packetTimestamp,
						CaptureLength: len(packetStream),
						Length:        len(packetStream),
					}
					err = writeTCPPacket(captureInfo, packetStream, p.clientConn)
					if err != nil {
						tplog.Fatal(err)
					}
				}
			}
		}
	}
}
