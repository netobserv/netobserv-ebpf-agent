package exporter

import (
	"context"
	"fmt"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	grpc "github.com/netobserv/netobserv-ebpf-agent/pkg/grpc/packet"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbpacket"

	"github.com/google/gopacket"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/anypb"
)

type GRPCPacketProto struct {
	hostIP     string
	hostPort   int
	clientConn *grpc.ClientConnection
}

var gplog = logrus.WithField("component", "packet/GRPCPackets")

// WritePacket writes the given packet data out to gRPC.
func writeGRPCPacket(ci gopacket.CaptureInfo, data []byte, conn *grpc.ClientConnection) error {
	if ci.CaptureLength != len(data) {
		return fmt.Errorf("capture length %d does not match data length %d", ci.CaptureLength, len(data))
	}
	if ci.CaptureLength > ci.Length {
		return fmt.Errorf("invalid capture info %+v:  capture length > length", ci)
	}
	gplog.Debugf("Sending Packet to client. Length: %d", len(data))
	b, err := GetPacketHeader(ci)
	if err != nil {
		return fmt.Errorf("error writing packet header: %w", err)
	}
	// write 16 byte packet header & data all at once
	_, err = conn.Client().Send(context.TODO(), &pbpacket.Packet{
		Pcap: &anypb.Any{
			Value: append(b, data...),
		},
	})
	return err
}

func StartGRPCPacketSend(hostIP string, hostPort int) (*GRPCPacketProto, error) {
	clientConn, err := grpc.ConnectClient(hostIP, hostPort)
	if err != nil {
		return nil, err
	}
	return &GRPCPacketProto{
		hostIP:     hostIP,
		hostPort:   hostPort,
		clientConn: clientConn,
	}, nil
}

func (p *GRPCPacketProto) ExportGRPCPackets(in <-chan []*flow.PacketRecord) {
	for packetRecord := range in {
		var errs []error
		for _, packet := range packetRecord {
			packetStream := packet.Stream
			packetTimestamp := packet.Time
			if len(packetStream) != 0 {
				captureInfo := gopacket.CaptureInfo{
					Timestamp:     packetTimestamp,
					CaptureLength: len(packetStream),
					Length:        len(packetStream),
				}
				if err := writeGRPCPacket(captureInfo, packetStream, p.clientConn); err != nil {
					errs = append(errs, err)
				}
			}
		}
		if len(errs) != 0 {
			gplog.Errorf("%d errors while sending packets:\n%s", len(errs), errs)
		}
	}
	if err := p.clientConn.Close(); err != nil {
		gplog.WithError(err).Warn("couldn't close packet export client")
	}
}
