// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type BpfDnsFlowId struct {
	SrcPort  uint16
	DstPort  uint16
	SrcIp    [16]uint8
	DstIp    [16]uint8
	Id       uint16
	IfIndex  uint32
	Protocol uint8
}

type BpfDnsRecordT struct {
	Id      uint16
	Flags   uint16
	Latency uint64
}

type BpfFlowId BpfFlowIdT

type BpfFlowIdT struct {
	EthProtocol       uint16
	Direction         uint8
	SrcMac            [6]uint8
	DstMac            [6]uint8
	SrcIp             [16]uint8
	DstIp             [16]uint8
	SrcPort           uint16
	DstPort           uint16
	TransportProtocol uint8
	IcmpType          uint8
	IcmpCode          uint8
	IfIndex           uint32
}

type BpfFlowMetrics BpfFlowMetricsT

type BpfFlowMetricsT struct {
	Packets         uint32
	Bytes           uint64
	StartMonoTimeTs uint64
	EndMonoTimeTs   uint64
	Flags           uint16
	Errno           uint8
	TcpDrops        BpfTcpDropsT
	DnsRecord       BpfDnsRecordT
	FlowRtt         uint64
}

type BpfFlowRecordT struct {
	Id      BpfFlowId
	Metrics BpfFlowMetrics
}

type BpfFlowSeqId struct {
	SrcPort uint16
	DstPort uint16
	SrcIp   [16]uint8
	DstIp   [16]uint8
	SeqId   uint32
}

type BpfTcpDropsT struct {
	Packets         uint32
	Bytes           uint64
	LatestFlags     uint16
	LatestState     uint8
	LatestDropCause uint32
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
}

// BpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfProgramSpecs struct {
	EgressFlowParse  *ebpf.ProgramSpec `ebpf:"egress_flow_parse"`
	IngressFlowParse *ebpf.ProgramSpec `ebpf:"ingress_flow_parse"`
	KfreeSkb         *ebpf.ProgramSpec `ebpf:"kfree_skb"`
	TraceNetPackets  *ebpf.ProgramSpec `ebpf:"trace_net_packets"`
}

// BpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfMapSpecs struct {
	AggregatedFlows *ebpf.MapSpec `ebpf:"aggregated_flows"`
	DirectFlows     *ebpf.MapSpec `ebpf:"direct_flows"`
	DnsFlows        *ebpf.MapSpec `ebpf:"dns_flows"`
	FlowSequences   *ebpf.MapSpec `ebpf:"flow_sequences"`
}

// BpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfObjects struct {
	BpfPrograms
	BpfMaps
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
	AggregatedFlows *ebpf.Map `ebpf:"aggregated_flows"`
	DirectFlows     *ebpf.Map `ebpf:"direct_flows"`
	DnsFlows        *ebpf.Map `ebpf:"dns_flows"`
	FlowSequences   *ebpf.Map `ebpf:"flow_sequences"`
}

func (m *BpfMaps) Close() error {
	return _BpfClose(
		m.AggregatedFlows,
		m.DirectFlows,
		m.DnsFlows,
		m.FlowSequences,
	)
}

// BpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfPrograms struct {
	EgressFlowParse  *ebpf.Program `ebpf:"egress_flow_parse"`
	IngressFlowParse *ebpf.Program `ebpf:"ingress_flow_parse"`
	KfreeSkb         *ebpf.Program `ebpf:"kfree_skb"`
	TraceNetPackets  *ebpf.Program `ebpf:"trace_net_packets"`
}

func (p *BpfPrograms) Close() error {
	return _BpfClose(
		p.EgressFlowParse,
		p.IngressFlowParse,
		p.KfreeSkb,
		p.TraceNetPackets,
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
//go:embed bpf_bpfel.o
var _BpfBytes []byte
