// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type BpfAdditionalMetrics struct {
	StartMonoTimeTs  uint64
	EndMonoTimeTs    uint64
	DnsRecord        BpfDnsRecordT
	PktDrops         BpfPktDropsT
	FlowRtt          uint64
	NetworkEvents    [4][8]uint8
	TranslatedFlow   BpfTranslatedFlowT
	EthProtocol      uint16
	NetworkEventsIdx uint8
	_                [7]byte
}

type BpfDirectionT uint32

const (
	BpfDirectionTINGRESS       BpfDirectionT = 0
	BpfDirectionTEGRESS        BpfDirectionT = 1
	BpfDirectionTMAX_DIRECTION BpfDirectionT = 2
)

type BpfDnsFlowId struct {
	SrcPort  uint16
	DstPort  uint16
	SrcIp    [16]uint8
	DstIp    [16]uint8
	Id       uint16
	Protocol uint8
	_        [1]byte
}

type BpfDnsRecordT struct {
	Latency uint64
	Id      uint16
	Flags   uint16
	Errno   uint8
	_       [3]byte
}

type BpfFilterActionT uint32

const (
	BpfFilterActionTACCEPT             BpfFilterActionT = 0
	BpfFilterActionTREJECT             BpfFilterActionT = 1
	BpfFilterActionTMAX_FILTER_ACTIONS BpfFilterActionT = 2
)

type BpfFilterKeyT struct {
	PrefixLen uint32
	IpData    [16]uint8
}

type BpfFilterValueT struct {
	Protocol          uint8
	_                 [1]byte
	DstPortStart      uint16
	DstPortEnd        uint16
	DstPort1          uint16
	DstPort2          uint16
	SrcPortStart      uint16
	SrcPortEnd        uint16
	SrcPort1          uint16
	SrcPort2          uint16
	PortStart         uint16
	PortEnd           uint16
	Port1             uint16
	Port2             uint16
	IcmpType          uint8
	IcmpCode          uint8
	Direction         BpfDirectionT
	Action            BpfFilterActionT
	TcpFlags          BpfTcpFlagsT
	FilterDrops       uint8
	_                 [3]byte
	Sample            uint32
	DoPeerCIDR_lookup uint8
	_                 [3]byte
}

type BpfFlowId BpfFlowIdT

type BpfFlowIdT struct {
	SrcIp             [16]uint8
	DstIp             [16]uint8
	SrcPort           uint16
	DstPort           uint16
	TransportProtocol uint8
	IcmpType          uint8
	IcmpCode          uint8
	_                 [1]byte
}

type BpfFlowMetrics BpfFlowMetricsT

type BpfFlowMetricsT struct {
	StartMonoTimeTs    uint64
	EndMonoTimeTs      uint64
	Bytes              uint64
	Packets            uint32
	EthProtocol        uint16
	Flags              uint16
	SrcMac             [6]uint8
	DstMac             [6]uint8
	IfIndexFirstSeen   uint32
	Lock               struct{ Val uint32 }
	Sampling           uint32
	DirectionFirstSeen uint8
	Errno              uint8
	Dscp               uint8
	NbObservedIntf     uint8
	ObservedDirection  [6]uint8
	_                  [2]byte
	ObservedIntf       [6]uint32
	_                  [4]byte
}

type BpfFlowRecordT struct {
	Id      BpfFlowId
	Metrics BpfFlowMetrics
}

type BpfGlobalCountersKeyT uint32

const (
	BpfGlobalCountersKeyTHASHMAP_FLOWS_DROPPED               BpfGlobalCountersKeyT = 0
	BpfGlobalCountersKeyTHASHMAP_FAIL_UPDATE_DNS             BpfGlobalCountersKeyT = 1
	BpfGlobalCountersKeyTFILTER_REJECT                       BpfGlobalCountersKeyT = 2
	BpfGlobalCountersKeyTFILTER_ACCEPT                       BpfGlobalCountersKeyT = 3
	BpfGlobalCountersKeyTFILTER_NOMATCH                      BpfGlobalCountersKeyT = 4
	BpfGlobalCountersKeyTNETWORK_EVENTS_ERR                  BpfGlobalCountersKeyT = 5
	BpfGlobalCountersKeyTNETWORK_EVENTS_ERR_GROUPID_MISMATCH BpfGlobalCountersKeyT = 6
	BpfGlobalCountersKeyTNETWORK_EVENTS_ERR_UPDATE_MAP_FLOWS BpfGlobalCountersKeyT = 7
	BpfGlobalCountersKeyTNETWORK_EVENTS_GOOD                 BpfGlobalCountersKeyT = 8
	BpfGlobalCountersKeyTOBSERVED_INTF_MISSED                BpfGlobalCountersKeyT = 9
	BpfGlobalCountersKeyTMAX_COUNTERS                        BpfGlobalCountersKeyT = 10
)

type BpfPktDropsT struct {
	Bytes           uint64
	Packets         uint32
	LatestDropCause uint32
	LatestFlags     uint16
	LatestState     uint8
	_               [5]byte
}

type BpfTcpFlagsT uint32

const (
	BpfTcpFlagsTFIN_FLAG     BpfTcpFlagsT = 1
	BpfTcpFlagsTSYN_FLAG     BpfTcpFlagsT = 2
	BpfTcpFlagsTRST_FLAG     BpfTcpFlagsT = 4
	BpfTcpFlagsTPSH_FLAG     BpfTcpFlagsT = 8
	BpfTcpFlagsTACK_FLAG     BpfTcpFlagsT = 16
	BpfTcpFlagsTURG_FLAG     BpfTcpFlagsT = 32
	BpfTcpFlagsTECE_FLAG     BpfTcpFlagsT = 64
	BpfTcpFlagsTCWR_FLAG     BpfTcpFlagsT = 128
	BpfTcpFlagsTSYN_ACK_FLAG BpfTcpFlagsT = 256
	BpfTcpFlagsTFIN_ACK_FLAG BpfTcpFlagsT = 512
	BpfTcpFlagsTRST_ACK_FLAG BpfTcpFlagsT = 1024
)

type BpfTranslatedFlowT struct {
	Saddr  [16]uint8
	Daddr  [16]uint8
	Sport  uint16
	Dport  uint16
	ZoneId uint16
}

// LoadBpf returns the embedded CollectionSpec for Bpf.
func LoadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Bpf: %w", err)
	}

	return spec, err
}

// LoadBpfObjects loads Bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*BpfObjects
//	*BpfPrograms
//	*BpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// BpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfSpecs struct {
	BpfProgramSpecs
	BpfMapSpecs
	BpfVariableSpecs
}

// BpfProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfProgramSpecs struct {
	KfreeSkb                *ebpf.ProgramSpec `ebpf:"kfree_skb"`
	NetworkEventsMonitoring *ebpf.ProgramSpec `ebpf:"network_events_monitoring"`
	TcEgressFlowParse       *ebpf.ProgramSpec `ebpf:"tc_egress_flow_parse"`
	TcEgressPcaParse        *ebpf.ProgramSpec `ebpf:"tc_egress_pca_parse"`
	TcIngressFlowParse      *ebpf.ProgramSpec `ebpf:"tc_ingress_flow_parse"`
	TcIngressPcaParse       *ebpf.ProgramSpec `ebpf:"tc_ingress_pca_parse"`
	TcpRcvFentry            *ebpf.ProgramSpec `ebpf:"tcp_rcv_fentry"`
	TcpRcvKprobe            *ebpf.ProgramSpec `ebpf:"tcp_rcv_kprobe"`
	TcxEgressFlowParse      *ebpf.ProgramSpec `ebpf:"tcx_egress_flow_parse"`
	TcxEgressPcaParse       *ebpf.ProgramSpec `ebpf:"tcx_egress_pca_parse"`
	TcxIngressFlowParse     *ebpf.ProgramSpec `ebpf:"tcx_ingress_flow_parse"`
	TcxIngressPcaParse      *ebpf.ProgramSpec `ebpf:"tcx_ingress_pca_parse"`
	TrackNatManipPkt        *ebpf.ProgramSpec `ebpf:"track_nat_manip_pkt"`
}

// BpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfMapSpecs struct {
	AdditionalFlowMetrics *ebpf.MapSpec `ebpf:"additional_flow_metrics"`
	AggregatedFlows       *ebpf.MapSpec `ebpf:"aggregated_flows"`
	DirectFlows           *ebpf.MapSpec `ebpf:"direct_flows"`
	DnsFlows              *ebpf.MapSpec `ebpf:"dns_flows"`
	FilterMap             *ebpf.MapSpec `ebpf:"filter_map"`
	GlobalCounters        *ebpf.MapSpec `ebpf:"global_counters"`
	PacketRecord          *ebpf.MapSpec `ebpf:"packet_record"`
	PeerFilterMap         *ebpf.MapSpec `ebpf:"peer_filter_map"`
}

// BpfVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfVariableSpecs struct {
	DnsPort                        *ebpf.VariableSpec `ebpf:"dns_port"`
	EnableDnsTracking              *ebpf.VariableSpec `ebpf:"enable_dns_tracking"`
	EnableFlowsFiltering           *ebpf.VariableSpec `ebpf:"enable_flows_filtering"`
	EnableNetworkEventsMonitoring  *ebpf.VariableSpec `ebpf:"enable_network_events_monitoring"`
	EnablePca                      *ebpf.VariableSpec `ebpf:"enable_pca"`
	EnablePktTranslationTracking   *ebpf.VariableSpec `ebpf:"enable_pkt_translation_tracking"`
	EnableRtt                      *ebpf.VariableSpec `ebpf:"enable_rtt"`
	FilterKey                      *ebpf.VariableSpec `ebpf:"filter_key"`
	FilterValue                    *ebpf.VariableSpec `ebpf:"filter_value"`
	HasFilterSampling              *ebpf.VariableSpec `ebpf:"has_filter_sampling"`
	NetworkEventsMonitoringGroupid *ebpf.VariableSpec `ebpf:"network_events_monitoring_groupid"`
	Sampling                       *ebpf.VariableSpec `ebpf:"sampling"`
	TraceMessages                  *ebpf.VariableSpec `ebpf:"trace_messages"`
	Unused8                        *ebpf.VariableSpec `ebpf:"unused8"`
	Unused9                        *ebpf.VariableSpec `ebpf:"unused9"`
}

// BpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfObjects struct {
	BpfPrograms
	BpfMaps
	BpfVariables
}

func (o *BpfObjects) Close() error {
	return _BpfClose(
		&o.BpfPrograms,
		&o.BpfMaps,
	)
}

// BpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfMaps struct {
	AdditionalFlowMetrics *ebpf.Map `ebpf:"additional_flow_metrics"`
	AggregatedFlows       *ebpf.Map `ebpf:"aggregated_flows"`
	DirectFlows           *ebpf.Map `ebpf:"direct_flows"`
	DnsFlows              *ebpf.Map `ebpf:"dns_flows"`
	FilterMap             *ebpf.Map `ebpf:"filter_map"`
	GlobalCounters        *ebpf.Map `ebpf:"global_counters"`
	PacketRecord          *ebpf.Map `ebpf:"packet_record"`
	PeerFilterMap         *ebpf.Map `ebpf:"peer_filter_map"`
}

func (m *BpfMaps) Close() error {
	return _BpfClose(
		m.AdditionalFlowMetrics,
		m.AggregatedFlows,
		m.DirectFlows,
		m.DnsFlows,
		m.FilterMap,
		m.GlobalCounters,
		m.PacketRecord,
		m.PeerFilterMap,
	)
}

// BpfVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfVariables struct {
	DnsPort                        *ebpf.Variable `ebpf:"dns_port"`
	EnableDnsTracking              *ebpf.Variable `ebpf:"enable_dns_tracking"`
	EnableFlowsFiltering           *ebpf.Variable `ebpf:"enable_flows_filtering"`
	EnableNetworkEventsMonitoring  *ebpf.Variable `ebpf:"enable_network_events_monitoring"`
	EnablePca                      *ebpf.Variable `ebpf:"enable_pca"`
	EnablePktTranslationTracking   *ebpf.Variable `ebpf:"enable_pkt_translation_tracking"`
	EnableRtt                      *ebpf.Variable `ebpf:"enable_rtt"`
	FilterKey                      *ebpf.Variable `ebpf:"filter_key"`
	FilterValue                    *ebpf.Variable `ebpf:"filter_value"`
	HasFilterSampling              *ebpf.Variable `ebpf:"has_filter_sampling"`
	NetworkEventsMonitoringGroupid *ebpf.Variable `ebpf:"network_events_monitoring_groupid"`
	Sampling                       *ebpf.Variable `ebpf:"sampling"`
	TraceMessages                  *ebpf.Variable `ebpf:"trace_messages"`
	Unused8                        *ebpf.Variable `ebpf:"unused8"`
	Unused9                        *ebpf.Variable `ebpf:"unused9"`
}

// BpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfPrograms struct {
	KfreeSkb                *ebpf.Program `ebpf:"kfree_skb"`
	NetworkEventsMonitoring *ebpf.Program `ebpf:"network_events_monitoring"`
	TcEgressFlowParse       *ebpf.Program `ebpf:"tc_egress_flow_parse"`
	TcEgressPcaParse        *ebpf.Program `ebpf:"tc_egress_pca_parse"`
	TcIngressFlowParse      *ebpf.Program `ebpf:"tc_ingress_flow_parse"`
	TcIngressPcaParse       *ebpf.Program `ebpf:"tc_ingress_pca_parse"`
	TcpRcvFentry            *ebpf.Program `ebpf:"tcp_rcv_fentry"`
	TcpRcvKprobe            *ebpf.Program `ebpf:"tcp_rcv_kprobe"`
	TcxEgressFlowParse      *ebpf.Program `ebpf:"tcx_egress_flow_parse"`
	TcxEgressPcaParse       *ebpf.Program `ebpf:"tcx_egress_pca_parse"`
	TcxIngressFlowParse     *ebpf.Program `ebpf:"tcx_ingress_flow_parse"`
	TcxIngressPcaParse      *ebpf.Program `ebpf:"tcx_ingress_pca_parse"`
	TrackNatManipPkt        *ebpf.Program `ebpf:"track_nat_manip_pkt"`
}

func (p *BpfPrograms) Close() error {
	return _BpfClose(
		p.KfreeSkb,
		p.NetworkEventsMonitoring,
		p.TcEgressFlowParse,
		p.TcEgressPcaParse,
		p.TcIngressFlowParse,
		p.TcIngressPcaParse,
		p.TcpRcvFentry,
		p.TcpRcvKprobe,
		p.TcxEgressFlowParse,
		p.TcxEgressPcaParse,
		p.TcxIngressFlowParse,
		p.TcxIngressPcaParse,
		p.TrackNatManipPkt,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_x86_bpfel.o
var _BpfBytes []byte
