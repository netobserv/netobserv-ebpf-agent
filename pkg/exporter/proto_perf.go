package exporter

import (
	"syscall"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func perfLogsToPB(inputRecords []*ebpf.BpfSockEventT, maxLen int) []*pbflow.Records {
	entries := make([]*pbflow.Record, 0, len(inputRecords))
	for _, record := range inputRecords {
		entries = append(entries, perfLogToPB(record))
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

func perfLogToPB(record *ebpf.BpfSockEventT) *pbflow.Record {
	if record.Family == syscall.AF_INET6 {
		return v6PerfLogToPB(record)
	}
	return v4PerfLogToPB(record)
}

func v4PerfLogToPB(e *ebpf.BpfSockEventT) *pbflow.Record {
	return &pbflow.Record{
		Network: &pbflow.Network{
			SrcAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv4{Ipv4: flow.IntEncodeV4(e.Saddr)}},
			DstAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv4{Ipv4: flow.IntEncodeV4(e.Daddr)}},
		},
		Transport: &pbflow.Transport{
			Protocol: syscall.IPPROTO_TCP,
			SrcPort:  uint32(e.Sport),
			DstPort:  uint32(e.Dport),
		},
		Bytes: e.RxBytes,
		TimeFlowStart: &timestamppb.Timestamp{
			Nanos: int32(e.TsUs),
		},
		TimeFlowEnd: &timestamppb.Timestamp{
			Nanos: int32(e.SpanUs + e.TsUs),
		},
	}
}

func v6PerfLogToPB(e *ebpf.BpfSockEventT) *pbflow.Record {
	return &pbflow.Record{
		Network: &pbflow.Network{
			SrcAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv6{Ipv6: e.Saddr[:]}},
			DstAddr: &pbflow.IP{IpFamily: &pbflow.IP_Ipv6{Ipv6: e.Daddr[:]}},
		},
		Transport: &pbflow.Transport{
			Protocol: syscall.IPPROTO_TCP,
			SrcPort:  uint32(e.Sport),
			DstPort:  uint32(e.Dport),
		},
		Bytes: e.RxBytes,
		TimeFlowStart: &timestamppb.Timestamp{
			Nanos: int32(e.TsUs),
		},
		TimeFlowEnd: &timestamppb.Timestamp{
			Nanos: int32(e.SpanUs + e.TsUs),
		},
	}
}
