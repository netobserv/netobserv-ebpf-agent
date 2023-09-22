package exporter

import (
	"encoding/binary"
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

// PCAP Magic number is fixed for each endianness.
const pcapMagicNumber = 0xA1B2C3D4
const versionMajor = 2
const versionMinor = 4
const nanosPerMicro = 1000

var plog = logrus.WithField("component", "packet/Packets")

// Setting Snapshot length to 0 sets it to maximum packet size
var snapshotlen uint32

func writePCAPFileHeader(snaplen uint32, linktype layers.LinkType, conn net.Conn) error {
	var buf [24]byte
	binary.LittleEndian.PutUint32(buf[0:4], pcapMagicNumber)
	binary.LittleEndian.PutUint16(buf[4:6], versionMajor)
	binary.LittleEndian.PutUint16(buf[6:8], versionMinor)
	binary.LittleEndian.PutUint32(buf[16:20], snaplen)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(linktype))
	_, err := conn.Write(buf[:])
	if err != nil {
		plog.Fatal(err)
	}
	return err
}

func writePacketHeader(ci gopacket.CaptureInfo, conn net.Conn) error {
	var buf [16]byte
	t := ci.Timestamp
	if t.IsZero() {
		return fmt.Errorf("incoming packet does not have a timestamp. Ignoring packet")
	}
	secs := t.Unix()
	usecs := t.Nanosecond() / nanosPerMicro
	binary.LittleEndian.PutUint32(buf[0:4], uint32(secs))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(usecs))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(ci.CaptureLength))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(ci.Length))
	_, err := conn.Write(buf[:])
	if err != nil {
		plog.Fatal(err)
	}
	return err
}

// WritePacket writes the given packet data out to the file.
func writePacket(ci gopacket.CaptureInfo, data []byte, conn net.Conn) error {
	if ci.CaptureLength != len(data) {
		return fmt.Errorf("capture length %d does not match data length %d", ci.CaptureLength, len(data))
	}
	if ci.CaptureLength > ci.Length {
		return fmt.Errorf("invalid capture info %+v:  capture length > length", ci)
	}
	plog.Debugf("Sending Packet to client. Length: %d", len(data))
	//Write 16 byte packet header
	if err := writePacketHeader(ci, conn); err != nil {
		return fmt.Errorf("error writing packet header: %w", err)
	}

	_, err := conn.Write(data)
	if err != nil {
		plog.Fatal(err)
	}
	return err
}

// FIXME: Only after client connects to it, the agent starts collecting and sending packets.
// This behavior needs to be fixed.
func StartPCAPSend(hostPort string) (*PCAPStream, error) {
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

func (p *PCAPStream) ExportFlows(in <-chan []*flow.PacketRecord) {

	//Create handler by opening PCAP stream - Write 24 byte size PCAP File Header
	err := writePCAPFileHeader(snapshotlen, layers.LinkTypeEthernet, p.clientConn)
	if err != nil {
		plog.Fatal(err)
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
					err = writePacket(captureInfo, packetStream, p.clientConn)
					if err != nil {
						plog.Fatal(err)
					}
				}
			}
		}
	}

}
