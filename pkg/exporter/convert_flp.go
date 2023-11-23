package exporter

import (
	"syscall"
	"time"

	"github.com/mdlayher/ethernet"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/decode"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
)

// ConvertToFLP converts the flow from Agent inner model into FLP GenericMap model
func ConvertToFLP(fr *flow.Record) config.GenericMap {
	if fr == nil {
		return config.GenericMap{}
	}
	srcMAC := flow.MacAddr(fr.Id.SrcMac)
	dstMAC := flow.MacAddr(fr.Id.DstMac)
	out := config.GenericMap{
		"FlowDirection":   int(fr.Id.Direction),
		"SrcMac":          srcMAC.String(),
		"DstMac":          dstMAC.String(),
		"Etype":           fr.Id.EthProtocol,
		"Duplicate":       fr.Duplicate,
		"TimeFlowStartMs": fr.TimeFlowStart.UnixMilli(),
		"TimeFlowEndMs":   fr.TimeFlowEnd.UnixMilli(),
		"TimeReceived":    time.Now().Unix(),
		"Interface":       fr.Interface,
		"AgentIP":         fr.AgentIP.String(),
	}

	if fr.Metrics.Bytes != 0 {
		out["Bytes"] = fr.Metrics.Bytes
	}

	if fr.Metrics.Packets != 0 {
		out["Packets"] = fr.Metrics.Packets
	}

	if fr.Id.EthProtocol == uint16(ethernet.EtherTypeIPv4) || fr.Id.EthProtocol == uint16(ethernet.EtherTypeIPv6) {
		out["SrcAddr"] = flow.IP(fr.Id.SrcIp).String()
		out["DstAddr"] = flow.IP(fr.Id.DstIp).String()
		out["Proto"] = fr.Id.TransportProtocol
		out["Dscp"] = fr.Metrics.Dscp

		if fr.Id.TransportProtocol == syscall.IPPROTO_ICMP || fr.Id.TransportProtocol == syscall.IPPROTO_ICMPV6 {
			out["IcmpType"] = fr.Id.IcmpType
			out["IcmpCode"] = fr.Id.IcmpCode
		} else if fr.Id.TransportProtocol == syscall.IPPROTO_TCP || fr.Id.TransportProtocol == syscall.IPPROTO_UDP || fr.Id.TransportProtocol == syscall.IPPROTO_SCTP {
			out["SrcPort"] = fr.Id.SrcPort
			out["DstPort"] = fr.Id.DstPort
			if fr.Id.TransportProtocol == syscall.IPPROTO_TCP {
				out["Flags"] = fr.Metrics.Flags
			}
		}

		out["DnsErrno"] = fr.Metrics.DnsRecord.Errno
		dnsID := fr.Metrics.DnsRecord.Id
		if dnsID != 0 {
			out["DnsId"] = dnsID
			out["DnsFlags"] = fr.Metrics.DnsRecord.Flags
			out["DnsFlagsResponseCode"] = decode.DNSRcodeToStr(uint32(fr.Metrics.DnsRecord.Flags) & 0xF)
			if fr.Metrics.DnsRecord.Latency != 0 {
				out["DnsLatencyMs"] = fr.DNSLatency.Milliseconds()
			}
			// Not sure about the logic here, why erasing errno?
			out["DnsErrno"] = uint32(0)
		}
	}

	if fr.Metrics.PktDrops.LatestDropCause != 0 {
		out["PktDropBytes"] = fr.Metrics.PktDrops.Bytes
		out["PktDropPackets"] = fr.Metrics.PktDrops.Packets
		out["PktDropLatestFlags"] = fr.Metrics.PktDrops.LatestFlags
		out["PktDropLatestState"] = decode.TCPStateToStr(uint32(fr.Metrics.PktDrops.LatestState))
		out["PktDropLatestDropCause"] = decode.PktDropCauseToStr(fr.Metrics.PktDrops.LatestDropCause)
	}

	if fr.TimeFlowRtt != 0 {
		out["TimeFlowRttNs"] = fr.TimeFlowRtt.Nanoseconds()
	}
	return out
}
