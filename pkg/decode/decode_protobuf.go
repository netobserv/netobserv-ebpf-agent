package decode

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"

	"github.com/mdlayher/ethernet"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	skbDropReasonSubsystemShift    = 16
	skbDropReasonSubSysCore        = (0 << skbDropReasonSubsystemShift)
	skbDropReasonSubSysOpenVSwitch = (3 << skbDropReasonSubsystemShift)
)

// Protobuf decodes protobuf flow records definitions, as forwarded by
// ingest.NetObservAgent, into a Generic Map that follows the same naming conventions
// as the IPFIX flows from ingest.IngestCollector
type Protobuf struct {
}

func NewProtobuf() (*Protobuf, error) {
	log.Debugf("entering NewProtobuf")
	return &Protobuf{}, nil
}

// Decode decodes the protobuf raw flows and returns a list of GenericMaps representing all
// the flows there
func (p *Protobuf) Decode(rawFlow []byte) (config.GenericMap, error) {
	record := pbflow.Record{}
	if err := proto.Unmarshal(rawFlow, &record); err != nil {
		return nil, fmt.Errorf("unmarshaling ProtoBuf record: %w", err)
	}
	return PBFlowToMap(&record), nil
}

func PBFlowToMap(flow *pbflow.Record) config.GenericMap {
	if flow == nil {
		return config.GenericMap{}
	}
	out := config.GenericMap{
		"FlowDirection":   int(flow.Direction.Number()),
		"SrcMac":          macToStr(flow.DataLink.GetSrcMac()),
		"DstMac":          macToStr(flow.DataLink.GetDstMac()),
		"Etype":           flow.EthProtocol,
		"Duplicate":       flow.Duplicate,
		"TimeFlowStartMs": flow.TimeFlowStart.AsTime().UnixMilli(),
		"TimeFlowEndMs":   flow.TimeFlowEnd.AsTime().UnixMilli(),
		"TimeReceived":    time.Now().Unix(),
		"Interface":       flow.Interface,
		"AgentIP":         ipToStr(flow.AgentIp),
	}

	if flow.Bytes != 0 {
		out["Bytes"] = flow.Bytes
	}

	if flow.Packets != 0 {
		out["Packets"] = flow.Packets
	}
	var interfaces []interface{}
	var flowDirections []interface{}

	if len(flow.GetDupList()) != 0 {
		for _, entry := range flow.GetDupList() {
			interfaces = append(interfaces, entry.Interface)
			flowDirections = append(flowDirections, entry.Direction)
		}
		out["Interfaces"] = interfaces
		out["FlowDirections"] = flowDirections
	}

	ethType := ethernet.EtherType(flow.EthProtocol)
	if ethType == ethernet.EtherTypeIPv4 || ethType == ethernet.EtherTypeIPv6 {
		out["SrcAddr"] = ipToStr(flow.Network.GetSrcAddr())
		out["DstAddr"] = ipToStr(flow.Network.GetDstAddr())
		out["Proto"] = flow.Transport.GetProtocol()
		out["Dscp"] = flow.Network.GetDscp()
		proto := flow.Transport.GetProtocol()
		if proto == syscall.IPPROTO_ICMP || proto == syscall.IPPROTO_ICMPV6 {
			out["IcmpType"] = flow.GetIcmpType()
			out["IcmpCode"] = flow.GetIcmpCode()
		}

		if proto == syscall.IPPROTO_TCP || proto == syscall.IPPROTO_UDP || proto == syscall.IPPROTO_SCTP {
			if proto == syscall.IPPROTO_TCP {
				out["SrcPort"] = flow.Transport.GetSrcPort()
				out["DstPort"] = flow.Transport.GetDstPort()
				out["Flags"] = flow.Flags
			} else {
				out["SrcPort"] = flow.Transport.GetSrcPort()
				out["DstPort"] = flow.Transport.GetDstPort()
			}
		}

		out["DnsErrno"] = flow.GetDnsErrno()
		if flow.GetDnsId() != 0 {
			out["DnsLatencyMs"] = flow.DnsLatency.AsDuration().Milliseconds()
			out["DnsId"] = flow.GetDnsId()
			out["DnsFlags"] = flow.GetDnsFlags()
			out["DnsFlagsResponseCode"] = DNSRcodeToStr(flow.GetDnsFlags() & 0xF)
			out["DnsErrno"] = uint32(0)
		}
	}

	if flow.GetPktDropLatestDropCause() != 0 {
		out["PktDropBytes"] = flow.PktDropBytes
		out["PktDropPackets"] = flow.PktDropPackets
		out["PktDropLatestFlags"] = flow.GetPktDropLatestFlags()
		out["PktDropLatestState"] = TCPStateToStr(flow.GetPktDropLatestState())
		out["PktDropLatestDropCause"] = PktDropCauseToStr(flow.GetPktDropLatestDropCause())
	}

	if flow.TimeFlowRtt.AsDuration().Nanoseconds() != 0 {
		out["TimeFlowRttNs"] = flow.TimeFlowRtt.AsDuration().Nanoseconds()
	}
	return out
}

func ipToStr(ip *pbflow.IP) string {
	if ip.GetIpv6() != nil {
		return net.IP(ip.GetIpv6()).String()
	}
	n := ip.GetIpv4()
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(n>>24), byte(n>>16), byte(n>>8), byte(n))

}

func macToStr(mac uint64) string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		uint8(mac>>40),
		uint8(mac>>32),
		uint8(mac>>24),
		uint8(mac>>16),
		uint8(mac>>8),
		uint8(mac))
}

// TCPStateToStr is based on kernel TCP state definition
// https://elixir.bootlin.com/linux/v6.3/source/include/net/tcp_states.h#L12
func TCPStateToStr(state uint32) string {
	switch state {
	case 1:
		return "TCP_ESTABLISHED"
	case 2:
		return "TCP_SYN_SENT"
	case 3:
		return "TCP_SYN_RECV"
	case 4:
		return "TCP_FIN_WAIT1"
	case 5:
		return "TCP_FIN_WAIT2"
	case 6:
		return "TCP_CLOSE"
	case 7:
		return "TCP_CLOSE_WAIT"
	case 8:
		return "TCP_LAST_ACK"
	case 9:
		return "TCP_LISTEN"
	case 10:
		return "TCP_CLOSING"
	case 11:
		return "TCP_NEW_SYN_RECV"
	}
	return "TCP_INVALID_STATE"
}

// PktDropCauseToStr is based on kernel drop cause definition
// https://elixir.bootlin.com/linux/latest/source/include/net/dropreason.h#L88
// nolint:cyclop
func PktDropCauseToStr(dropCause uint32) string {
	switch dropCause {
	case skbDropReasonSubSysCore + 2:
		return "SKB_DROP_REASON_NOT_SPECIFIED"
	case skbDropReasonSubSysCore + 3:
		return "SKB_DROP_REASON_NO_SOCKET"
	case skbDropReasonSubSysCore + 4:
		return "SKB_DROP_REASON_PKT_TOO_SMALL"
	case skbDropReasonSubSysCore + 5:
		return "SKB_DROP_REASON_TCP_CSUM"
	case skbDropReasonSubSysCore + 6:
		return "SKB_DROP_REASON_SOCKET_FILTER"
	case skbDropReasonSubSysCore + 7:
		return "SKB_DROP_REASON_UDP_CSUM"
	case skbDropReasonSubSysCore + 8:
		return "SKB_DROP_REASON_NETFILTER_DROP"
	case skbDropReasonSubSysCore + 9:
		return "SKB_DROP_REASON_OTHERHOST"
	case skbDropReasonSubSysCore + 10:
		return "SKB_DROP_REASON_IP_CSUM"
	case skbDropReasonSubSysCore + 11:
		return "SKB_DROP_REASON_IP_INHDR"
	case skbDropReasonSubSysCore + 12:
		return "SKB_DROP_REASON_IP_RPFILTER"
	case skbDropReasonSubSysCore + 13:
		return "SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST"
	case skbDropReasonSubSysCore + 14:
		return "SKB_DROP_REASON_XFRM_POLICY"
	case skbDropReasonSubSysCore + 15:
		return "SKB_DROP_REASON_IP_NOPROTO"
	case skbDropReasonSubSysCore + 16:
		return "SKB_DROP_REASON_SOCKET_RCVBUFF"
	case skbDropReasonSubSysCore + 17:
		return "SKB_DROP_REASON_PROTO_MEM"
	case skbDropReasonSubSysCore + 18:
		return "SKB_DROP_REASON_TCP_MD5NOTFOUND"
	case skbDropReasonSubSysCore + 19:
		return "SKB_DROP_REASON_TCP_MD5UNEXPECTED"
	case skbDropReasonSubSysCore + 20:
		return "SKB_DROP_REASON_TCP_MD5FAILURE"
	case skbDropReasonSubSysCore + 21:
		return "SKB_DROP_REASON_SOCKET_BACKLOG"
	case skbDropReasonSubSysCore + 22:
		return "SKB_DROP_REASON_TCP_FLAGS"
	case skbDropReasonSubSysCore + 23:
		return "SKB_DROP_REASON_TCP_ZEROWINDOW"
	case skbDropReasonSubSysCore + 24:
		return "SKB_DROP_REASON_TCP_OLD_DATA"
	case skbDropReasonSubSysCore + 25:
		return "SKB_DROP_REASON_TCP_OVERWINDOW"
	case skbDropReasonSubSysCore + 26:
		return "SKB_DROP_REASON_TCP_OFOMERGE"
	case skbDropReasonSubSysCore + 27:
		return "SKB_DROP_REASON_TCP_RFC7323_PAWS"
	case skbDropReasonSubSysCore + 28:
		return "SKB_DROP_REASON_TCP_INVALID_SEQUENCE"
	case skbDropReasonSubSysCore + 29:
		return "SKB_DROP_REASON_TCP_RESET"
	case skbDropReasonSubSysCore + 30:
		return "SKB_DROP_REASON_TCP_INVALID_SYN"
	case skbDropReasonSubSysCore + 31:
		return "SKB_DROP_REASON_TCP_CLOSE"
	case skbDropReasonSubSysCore + 32:
		return "SKB_DROP_REASON_TCP_FASTOPEN"
	case skbDropReasonSubSysCore + 33:
		return "SKB_DROP_REASON_TCP_OLD_ACK"
	case skbDropReasonSubSysCore + 34:
		return "SKB_DROP_REASON_TCP_TOO_OLD_ACK"
	case skbDropReasonSubSysCore + 35:
		return "SKB_DROP_REASON_TCP_ACK_UNSENT_DATA"
	case skbDropReasonSubSysCore + 36:
		return "SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE"
	case skbDropReasonSubSysCore + 37:
		return "SKB_DROP_REASON_TCP_OFO_DROP"
	case skbDropReasonSubSysCore + 38:
		return "SKB_DROP_REASON_IP_OUTNOROUTES"
	case skbDropReasonSubSysCore + 39:
		return "SKB_DROP_REASON_BPF_CGROUP_EGRESS"
	case skbDropReasonSubSysCore + 40:
		return "SKB_DROP_REASON_IPV6DISABLED"
	case skbDropReasonSubSysCore + 41:
		return "SKB_DROP_REASON_NEIGH_CREATEFAIL"
	case skbDropReasonSubSysCore + 42:
		return "SKB_DROP_REASON_NEIGH_FAILED"
	case skbDropReasonSubSysCore + 43:
		return "SKB_DROP_REASON_NEIGH_QUEUEFULL"
	case skbDropReasonSubSysCore + 44:
		return "SKB_DROP_REASON_NEIGH_DEAD"
	case skbDropReasonSubSysCore + 45:
		return "SKB_DROP_REASON_TC_EGRESS"
	case skbDropReasonSubSysCore + 46:
		return "SKB_DROP_REASON_QDISC_DROP"
	case skbDropReasonSubSysCore + 47:
		return "SKB_DROP_REASON_CPU_BACKLOG"
	case skbDropReasonSubSysCore + 48:
		return "SKB_DROP_REASON_XDP"
	case skbDropReasonSubSysCore + 49:
		return "SKB_DROP_REASON_TC_INGRESS"
	case skbDropReasonSubSysCore + 50:
		return "SKB_DROP_REASON_UNHANDLED_PROTO"
	case skbDropReasonSubSysCore + 51:
		return "SKB_DROP_REASON_SKB_CSUM"
	case skbDropReasonSubSysCore + 52:
		return "SKB_DROP_REASON_SKB_GSO_SEG"
	case skbDropReasonSubSysCore + 53:
		return "SKB_DROP_REASON_SKB_UCOPY_FAULT"
	case skbDropReasonSubSysCore + 54:
		return "SKB_DROP_REASON_DEV_HDR"
	case skbDropReasonSubSysCore + 55:
		return "SKB_DROP_REASON_DEV_READY"
	case skbDropReasonSubSysCore + 56:
		return "SKB_DROP_REASON_FULL_RING"
	case skbDropReasonSubSysCore + 57:
		return "SKB_DROP_REASON_NOMEM"
	case skbDropReasonSubSysCore + 58:
		return "SKB_DROP_REASON_HDR_TRUNC"
	case skbDropReasonSubSysCore + 59:
		return "SKB_DROP_REASON_TAP_FILTER"
	case skbDropReasonSubSysCore + 60:
		return "SKB_DROP_REASON_TAP_TXFILTER"
	case skbDropReasonSubSysCore + 61:
		return "SKB_DROP_REASON_ICMP_CSUM"
	case skbDropReasonSubSysCore + 62:
		return "SKB_DROP_REASON_INVALID_PROTO"
	case skbDropReasonSubSysCore + 63:
		return "SKB_DROP_REASON_IP_INADDRERRORS"
	case skbDropReasonSubSysCore + 64:
		return "SKB_DROP_REASON_IP_INNOROUTES"
	case skbDropReasonSubSysCore + 65:
		return "SKB_DROP_REASON_PKT_TOO_BIG"
	case skbDropReasonSubSysCore + 66:
		return "SKB_DROP_REASON_DUP_FRAG"
	case skbDropReasonSubSysCore + 67:
		return "SKB_DROP_REASON_FRAG_REASM_TIMEOUT"
	case skbDropReasonSubSysCore + 68:
		return "SKB_DROP_REASON_FRAG_TOO_FAR"
	case skbDropReasonSubSysCore + 69:
		return "SKB_DROP_REASON_TCP_MINTTL"
	case skbDropReasonSubSysCore + 70:
		return "SKB_DROP_REASON_IPV6_BAD_EXTHDR"
	case skbDropReasonSubSysCore + 71:
		return "SKB_DROP_REASON_IPV6_NDISC_FRAG"
	case skbDropReasonSubSysCore + 72:
		return "SKB_DROP_REASON_IPV6_NDISC_HOP_LIMIT"
	case skbDropReasonSubSysCore + 73:
		return "SKB_DROP_REASON_IPV6_NDISC_BAD_CODE"
	case skbDropReasonSubSysCore + 74:
		return "SKB_DROP_REASON_IPV6_NDISC_BAD_OPTIONS"
	case skbDropReasonSubSysCore + 75:
		return "SKB_DROP_REASON_IPV6_NDISC_NS_OTHERHOST"

	// ovs drop causes
	// https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git/tree/net/openvswitch/drop.h
	case skbDropReasonSubSysOpenVSwitch + 1:
		return "OVS_DROP_LAST_ACTION"
	case skbDropReasonSubSysOpenVSwitch + 2:
		return "OVS_DROP_ACTION_ERROR"
	case skbDropReasonSubSysOpenVSwitch + 3:
		return "OVS_DROP_EXPLICIT"
	case skbDropReasonSubSysOpenVSwitch + 4:
		return "OVS_DROP_EXPLICIT_WITH_ERROR"
	case skbDropReasonSubSysOpenVSwitch + 5:
		return "OVS_DROP_METER"
	case skbDropReasonSubSysOpenVSwitch + 6:
		return "OVS_DROP_RECURSION_LIMIT"
	case skbDropReasonSubSysOpenVSwitch + 7:
		return "OVS_DROP_DEFERRED_LIMIT"
	case skbDropReasonSubSysOpenVSwitch + 8:
		return "OVS_DROP_FRAG_L2_TOO_LONG"
	case skbDropReasonSubSysOpenVSwitch + 9:
		return "OVS_DROP_FRAG_INVALID_PROTO"
	case skbDropReasonSubSysOpenVSwitch + 10:
		return "OVS_DROP_CONNTRACK"
	case skbDropReasonSubSysOpenVSwitch + 11:
		return "OVS_DROP_IP_TTL"
	}
	return "SKB_DROP_UNKNOWN_CAUSE"
}

// DNSRcodeToStr decode DNS flags response code bits and return a string
// https://datatracker.ietf.org/doc/html/rfc2929#section-2.3
func DNSRcodeToStr(rcode uint32) string {
	switch rcode {
	case 0:
		return "NoError"
	case 1:
		return "FormErr"
	case 2:
		return "ServFail"
	case 3:
		return "NXDomain"
	case 4:
		return "NotImp"
	case 5:
		return "Refused"
	case 6:
		return "YXDomain"
	case 7:
		return "YXRRSet"
	case 8:
		return "NXRRSet"
	case 9:
		return "NotAuth"
	case 10:
		return "NotZone"
	case 16:
		return "BADVERS"
	case 17:
		return "BADKEY"
	case 18:
		return "BADTIME"
	case 19:
		return "BADMODE"
	case 20:
		return "BADNAME"
	case 21:
		return "BADALG"
	}
	return "UnDefined"
}
