package exporter

import (
	"context"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/grpc"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
)

var glog = logrus.WithField("component", "exporter/GRPCProto")

// GRPCProto flow exporter. Its ExportFlows method accepts slices of *flow.Record
// by its input channel, converts them to *pbflow.Records instances, and submits
// them to the collector.
type GRPCProto struct {
	hostPort   string
	clientConn *grpc.ClientConnection
}

func StartGRPCProto(hostPort string) (*GRPCProto, error) {
	clientConn, err := grpc.ConnectClient(hostPort)
	if err != nil {
		return nil, err
	}
	return &GRPCProto{
		hostPort:   hostPort,
		clientConn: clientConn,
	}, nil
}

// ExportFlows accepts slices of *flow.Record by its input channel, converts them
// to *pbflow.Records instances, and submits them to the collector.
func (g *GRPCProto) ExportFlows(input <-chan []*flow.Record) {
	log := glog.WithField("collector", g.hostPort)
	for inputRecords := range input {
		entries := make([]*pbflow.Record, 0, len(inputRecords))
		for _, record := range inputRecords {
			entries = append(entries, flowToPB(record))
		}
		log.Debugf("sending %d records", len(entries))
		if _, err := g.clientConn.Client().Send(context.TODO(), &pbflow.Records{
			Entries: entries,
		}); err != nil {
			log.WithError(err).Error("couldn't send flow records to collector")
		}

	}
	if err := g.clientConn.Close(); err != nil {
		log.WithError(err).Warn("couldn't close flow export client")
	}
}

func v4FlowToPB(fr *flow.Record) *pbflow.Record {
	return &pbflow.Record{
		EthProtocol: uint32(fr.Protocol),
		Direction:   pbflow.Direction(fr.Direction),
		DataLink: &pbflow.DataLink{
			SrcMac: macToUint64(&fr.DataLink.SrcMac),
			DstMac: macToUint64(&fr.DataLink.DstMac),
		},
		Network: &pbflow.Network{
			SrcAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv4{Ipv4: uint32(fr.Network.SrcAddr)}},
			DstAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv4{Ipv4: uint32(fr.Network.DstAddr)}},
		},
		Transport: &pbflow.Transport{
			Protocol: uint32(fr.Transport.Protocol),
			SrcPort:  uint32(fr.Transport.SrcPort),
			DstPort:  uint32(fr.Transport.DstPort),
		},
		Bytes: uint64(fr.Bytes),
		TimeFlowStart: &timestamppb.Timestamp{
			Seconds: fr.TimeFlowStart.Unix(),
			Nanos:   int32(fr.TimeFlowStart.Nanosecond()),
		},
		TimeFlowEnd: &timestamppb.Timestamp{
			Seconds: fr.TimeFlowEnd.Unix(),
			Nanos:   int32(fr.TimeFlowEnd.Nanosecond()),
		},
		Packets:   uint64(fr.Packets),
		Interface: fr.Interface,
	}
}

func v6FlowToPB(fr *flow.Record) *pbflow.Record {
	return &pbflow.Record{
		EthProtocol: uint32(fr.Protocol),
		Direction:   pbflow.Direction(fr.Direction),
		DataLink: &pbflow.DataLink{
			SrcMac: macToUint64(&fr.DataLink.SrcMac),
			DstMac: macToUint64(&fr.DataLink.DstMac),
		},
		Network: &pbflow.Network{
			SrcAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv6{Ipv6: []byte{fr.NetworkV6.SrcAddr[0],
				fr.NetworkV6.SrcAddr[1], fr.NetworkV6.SrcAddr[2], fr.NetworkV6.SrcAddr[3],
				fr.NetworkV6.SrcAddr[4], fr.NetworkV6.SrcAddr[5], fr.NetworkV6.SrcAddr[6],
				fr.NetworkV6.SrcAddr[7], fr.NetworkV6.SrcAddr[8], fr.NetworkV6.SrcAddr[9],
				fr.NetworkV6.SrcAddr[10], fr.NetworkV6.SrcAddr[11], fr.NetworkV6.SrcAddr[12],
				fr.NetworkV6.SrcAddr[13], fr.NetworkV6.SrcAddr[14], fr.NetworkV6.SrcAddr[15],}}},
			DstAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv6{Ipv6: []byte{fr.NetworkV6.DstAddr[0],
				fr.NetworkV6.DstAddr[1], fr.NetworkV6.DstAddr[2], fr.NetworkV6.DstAddr[3],
				fr.NetworkV6.DstAddr[4], fr.NetworkV6.DstAddr[5], fr.NetworkV6.DstAddr[6],
				fr.NetworkV6.DstAddr[7], fr.NetworkV6.DstAddr[8], fr.NetworkV6.DstAddr[9],
				fr.NetworkV6.DstAddr[10], fr.NetworkV6.DstAddr[11], fr.NetworkV6.DstAddr[12],
				fr.NetworkV6.DstAddr[13], fr.NetworkV6.DstAddr[14], fr.NetworkV6.DstAddr[15],}}},
		},
		Transport: &pbflow.Transport{
			Protocol: uint32(fr.Transport.Protocol),
			SrcPort:  uint32(fr.Transport.SrcPort),
			DstPort:  uint32(fr.Transport.DstPort),
		},
		Bytes: uint64(fr.Bytes),
		TimeFlowStart: &timestamppb.Timestamp{
			Seconds: fr.TimeFlowStart.Unix(),
			Nanos:   int32(fr.TimeFlowStart.Nanosecond()),
		},
		TimeFlowEnd: &timestamppb.Timestamp{
			Seconds: fr.TimeFlowEnd.Unix(),
			Nanos:   int32(fr.TimeFlowEnd.Nanosecond()),
		},
		Packets:   uint64(fr.Packets),
		Interface: fr.Interface,
	}
}

func flowToPB(fr *flow.Record) *pbflow.Record {
	if fr.Protocol == flow.IPv6Type {
		return v6FlowToPB(fr)
	}
	return v4FlowToPB(fr)
}

// Mac bytes are encoded in the same order as in the array. This is, a Mac
// like 11:22:33:44:55:66 will be encoded as 0x112233445566
func macToUint64(m *flow.MacAddr) uint64 {
	return uint64(m[5]) |
		(uint64(m[4]) << 8) |
		(uint64(m[3]) << 16) |
		(uint64(m[2]) << 24) |
		(uint64(m[1]) << 32) |
		(uint64(m[0]) << 40)
}
