package exporter

import (
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FlowsToPB is an auxiliary function to convert flow records, as returned by the eBPF agent,
// into protobuf-encoded messages ready to be sent to the collector via GRPC
func FlowsToPB(inputRecords []*flow.Record) *pbflow.Records {
	entries := make([]*pbflow.Record, 0, len(inputRecords))
	for _, record := range inputRecords {
		entries = append(entries, FlowToPB(record))
	}
	return &pbflow.Records{
		Entries: entries,
	}
}

// FlowToPB is an auxiliary function to convert a single flow record, as returned by the eBPF agent,
// into a protobuf-encoded message ready to be sent to the collector via kafka
func FlowToPB(record *flow.Record) *pbflow.Record {
	if record.EthProtocol == flow.IPv6Type {
		return v6FlowToPB(record)
	}
	return v4FlowToPB(record)
}

func v4FlowToPB(fr *flow.Record) *pbflow.Record {
	return &pbflow.Record{
		EthProtocol: uint32(fr.EthProtocol),
		Direction:   pbflow.Direction(fr.Direction),
		DataLink: &pbflow.DataLink{
			SrcMac: macToUint64(&fr.DataLink.SrcMac),
			DstMac: macToUint64(&fr.DataLink.DstMac),
		},
		Network: &pbflow.Network{
			SrcAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv4{Ipv4: fr.Network.SrcAddr.IntEncodeV4()}},
			DstAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv4{Ipv4: fr.Network.DstAddr.IntEncodeV4()}},
		},
		Transport: &pbflow.Transport{
			Protocol: uint32(fr.Transport.Protocol),
			SrcPort:  uint32(fr.Transport.SrcPort),
			DstPort:  uint32(fr.Transport.DstPort),
		},
		Bytes: fr.Bytes,
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
		Duplicate: fr.Duplicate,
	}
}

func v6FlowToPB(fr *flow.Record) *pbflow.Record {
	return &pbflow.Record{
		EthProtocol: uint32(fr.EthProtocol),
		Direction:   pbflow.Direction(fr.Direction),
		DataLink: &pbflow.DataLink{
			SrcMac: macToUint64(&fr.DataLink.SrcMac),
			DstMac: macToUint64(&fr.DataLink.DstMac),
		},
		Network: &pbflow.Network{
			SrcAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv6{Ipv6: fr.Network.SrcAddr[:]}},
			DstAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv6{Ipv6: fr.Network.DstAddr[:]}},
		},
		Transport: &pbflow.Transport{
			Protocol: uint32(fr.Transport.Protocol),
			SrcPort:  uint32(fr.Transport.SrcPort),
			DstPort:  uint32(fr.Transport.DstPort),
		},
		Bytes: fr.Bytes,
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
		Duplicate: fr.Duplicate,
	}
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
