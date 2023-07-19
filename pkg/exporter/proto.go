package exporter

import (
	"encoding/binary"
	"net"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// flowsToPB is an auxiliary function to convert flow records, as returned by the eBPF agent,
// into protobuf-encoded messages ready to be sent to the collector via GRPC
func flowsToPB(inputRecords []*flow.Record, maxLen int) []*pbflow.Records {
	entries := make([]*pbflow.Record, 0, len(inputRecords))
	for _, record := range inputRecords {
		entries = append(entries, flowToPB(record))
	}
	var records []*pbflow.Records
	for len(entries) > 0 {
		end := len(entries)
		if end > maxLen {
			end = maxLen
		}
		records = append(records, &pbflow.Records{Entries: entries[:end]})
		entries = entries[end:]
	}
	return records
}

// flowsToPB is an auxiliary function to convert a single flow record, as returned by the eBPF agent,
// into a protobuf-encoded message ready to be sent to the collector via kafka
func flowToPB(record *flow.Record) *pbflow.Record {
	if record.Id.EthProtocol == flow.IPv6Type {
		return v6FlowToPB(record)
	}
	return v4FlowToPB(record)
}

func v4FlowToPB(fr *flow.Record) *pbflow.Record {
	var pbflowRecord = pbflow.Record{
		EthProtocol: uint32(fr.Id.EthProtocol),
		Direction:   pbflow.Direction(fr.Id.Direction),
		DataLink: &pbflow.DataLink{
			SrcMac: macToUint64(&fr.Id.SrcMac),
			DstMac: macToUint64(&fr.Id.DstMac),
		},
		Network: &pbflow.Network{
			SrcAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv4{Ipv4: flow.IntEncodeV4(fr.Id.SrcIp)}},
			DstAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv4{Ipv4: flow.IntEncodeV4(fr.Id.DstIp)}},
		},
		Transport: &pbflow.Transport{
			Protocol: uint32(fr.Id.TransportProtocol),
			SrcPort:  uint32(fr.Id.SrcPort),
			DstPort:  uint32(fr.Id.DstPort),
		},
		IcmpType: uint32(fr.Id.IcmpType),
		IcmpCode: uint32(fr.Id.IcmpCode),
		Bytes:    fr.Metrics.Bytes,
		TimeFlowStart: &timestamppb.Timestamp{
			Seconds: fr.TimeFlowStart.Unix(),
			Nanos:   int32(fr.TimeFlowStart.Nanosecond()),
		},
		TimeFlowEnd: &timestamppb.Timestamp{
			Seconds: fr.TimeFlowEnd.Unix(),
			Nanos:   int32(fr.TimeFlowEnd.Nanosecond()),
		},
		Packets:                uint64(fr.Metrics.Packets),
		Duplicate:              fr.Duplicate,
		AgentIp:                agentIP(fr.AgentIP),
		Flags:                  uint32(fr.Metrics.Flags),
		Interface:              string(fr.Interface),
		PktDropBytes:           fr.Metrics.PktDrops.Bytes,
		PktDropPackets:         uint64(fr.Metrics.PktDrops.Packets),
		PktDropLatestFlags:     uint32(fr.Metrics.PktDrops.LatestFlags),
		PktDropLatestState:     uint32(fr.Metrics.PktDrops.LatestState),
		PktDropLatestDropCause: fr.Metrics.PktDrops.LatestDropCause,
		DnsId:                  uint32(fr.Metrics.DnsRecord.Id),
		DnsFlags:               uint32(fr.Metrics.DnsRecord.Flags),
		TimeFlowRtt:            durationpb.New(fr.TimeFlowRtt),
	}
	if fr.Metrics.DnsRecord.Latency != 0 {
		pbflowRecord.DnsLatency = durationpb.New(fr.DNSLatency)
	}
	return &pbflowRecord
}

func v6FlowToPB(fr *flow.Record) *pbflow.Record {
	var pbflowRecord = pbflow.Record{
		EthProtocol: uint32(fr.Id.EthProtocol),
		Direction:   pbflow.Direction(fr.Id.Direction),
		DataLink: &pbflow.DataLink{
			SrcMac: macToUint64(&fr.Id.SrcMac),
			DstMac: macToUint64(&fr.Id.DstMac),
		},
		Network: &pbflow.Network{
			SrcAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv6{Ipv6: fr.Id.SrcIp[:]}},
			DstAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv6{Ipv6: fr.Id.DstIp[:]}},
		},
		Transport: &pbflow.Transport{
			Protocol: uint32(fr.Id.TransportProtocol),
			SrcPort:  uint32(fr.Id.SrcPort),
			DstPort:  uint32(fr.Id.DstPort),
		},
		IcmpType: uint32(fr.Id.IcmpType),
		IcmpCode: uint32(fr.Id.IcmpCode),
		Bytes:    fr.Metrics.Bytes,
		TimeFlowStart: &timestamppb.Timestamp{
			Seconds: fr.TimeFlowStart.Unix(),
			Nanos:   int32(fr.TimeFlowStart.Nanosecond()),
		},
		TimeFlowEnd: &timestamppb.Timestamp{
			Seconds: fr.TimeFlowEnd.Unix(),
			Nanos:   int32(fr.TimeFlowEnd.Nanosecond()),
		},
		Packets:                uint64(fr.Metrics.Packets),
		Flags:                  uint32(fr.Metrics.Flags),
		Interface:              fr.Interface,
		Duplicate:              fr.Duplicate,
		AgentIp:                agentIP(fr.AgentIP),
		PktDropBytes:           fr.Metrics.PktDrops.Bytes,
		PktDropPackets:         uint64(fr.Metrics.PktDrops.Packets),
		PktDropLatestFlags:     uint32(fr.Metrics.PktDrops.LatestFlags),
		PktDropLatestState:     uint32(fr.Metrics.PktDrops.LatestState),
		PktDropLatestDropCause: fr.Metrics.PktDrops.LatestDropCause,
		DnsId:                  uint32(fr.Metrics.DnsRecord.Id),
		DnsFlags:               uint32(fr.Metrics.DnsRecord.Flags),
		TimeFlowRtt:            durationpb.New(fr.TimeFlowRtt),
	}
	if fr.Metrics.DnsRecord.Latency != 0 {
		pbflowRecord.DnsLatency = durationpb.New(fr.DNSLatency)
	}
	return &pbflowRecord
}

// Mac bytes are encoded in the same order as in the array. This is, a Mac
// like 11:22:33:44:55:66 will be encoded as 0x112233445566
func macToUint64(m *[flow.MacLen]uint8) uint64 {
	return uint64(m[5]) |
		(uint64(m[4]) << 8) |
		(uint64(m[3]) << 16) |
		(uint64(m[2]) << 24) |
		(uint64(m[1]) << 32) |
		(uint64(m[0]) << 40)
}

func agentIP(nip net.IP) *pbflow.IP {
	if ip := nip.To4(); ip != nil {
		return &pbflow.IP{IpFamily: &pbflow.IP_Ipv4{Ipv4: binary.BigEndian.Uint32(ip)}}
	}
	// IPv6 address
	return &pbflow.IP{IpFamily: &pbflow.IP_Ipv6{Ipv6: nip}}
}
