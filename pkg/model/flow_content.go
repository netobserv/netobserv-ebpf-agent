package model

import (
	"math"

	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
)

type BpfFlowContent struct {
	*ebpf.FlowsBpfFlowMetrics
	DNSMetrics           *ebpf.FlowsBpfDnsMetrics
	PktDropMetrics       *ebpf.FlowsBpfPktDropMetrics
	NetworkEventsMetrics *ebpf.FlowsBpfNetworkEventsMetrics
	XlatMetrics          *ebpf.FlowsBpfXlatMetrics
	AdditionalMetrics    *ebpf.FlowsBpfAdditionalMetrics
	QuicMetrics          *ebpf.FlowsBpfQuicMetrics
}

// nolint:gocritic // hugeParam: metric is reported as heavy; but it needs to be copied anyway, we don't want a pointer here
func NewBpfFlowContent(metrics ebpf.FlowsBpfFlowMetrics) BpfFlowContent {
	return BpfFlowContent{FlowsBpfFlowMetrics: &metrics}
}

func (p *BpfFlowContent) AccumulateBase(other *ebpf.FlowsBpfFlowMetrics) {
	p.FlowsBpfFlowMetrics = AccumulateBase(p.FlowsBpfFlowMetrics, other)
}

func AccumulateBase(p *ebpf.FlowsBpfFlowMetrics, other *ebpf.FlowsBpfFlowMetrics) *ebpf.FlowsBpfFlowMetrics {
	if other == nil {
		return p
	}
	if p == nil {
		return other
	}
	// time == 0 if the value has not been yet set
	if p.StartMonoTimeTs == 0 || (p.StartMonoTimeTs > other.StartMonoTimeTs && other.StartMonoTimeTs != 0) {
		p.StartMonoTimeTs = other.StartMonoTimeTs
	}
	if p.EndMonoTimeTs == 0 || p.EndMonoTimeTs < other.EndMonoTimeTs {
		p.EndMonoTimeTs = other.EndMonoTimeTs
	}
	p.Bytes += other.Bytes
	p.Packets += other.Packets
	p.Flags |= other.Flags
	if other.EthProtocol != 0 {
		p.EthProtocol = other.EthProtocol
	}
	if AllZerosMac(p.SrcMac) {
		p.SrcMac = other.SrcMac
	}
	if AllZerosMac(p.DstMac) {
		p.DstMac = other.DstMac
	}
	if other.Dscp != 0 {
		p.Dscp = other.Dscp
	}
	if other.Sampling != 0 {
		p.Sampling = other.Sampling
	}
	return p
}

func (p *BpfFlowContent) buildBaseFromAdditional(start, end uint64, ethProto uint16) {
	// Accumulate time into base metrics if unset
	if p.FlowsBpfFlowMetrics.StartMonoTimeTs == 0 || (p.FlowsBpfFlowMetrics.StartMonoTimeTs > start && start != 0) {
		p.FlowsBpfFlowMetrics.StartMonoTimeTs = start
	}
	if p.FlowsBpfFlowMetrics.EndMonoTimeTs == 0 || p.FlowsBpfFlowMetrics.EndMonoTimeTs < end {
		p.FlowsBpfFlowMetrics.EndMonoTimeTs = end
	}
	if p.FlowsBpfFlowMetrics.EthProtocol == 0 {
		p.FlowsBpfFlowMetrics.EthProtocol = ethProto
	}
}

func (p *BpfFlowContent) AccumulateDNS(other *ebpf.FlowsBpfDnsMetrics) {
	if other == nil {
		return
	}
	p.buildBaseFromAdditional(other.StartMonoTimeTs, other.EndMonoTimeTs, other.EthProtocol)
	if p.DNSMetrics == nil {
		p.DNSMetrics = other
		return
	}
	// DNS
	p.DNSMetrics.Flags |= other.Flags
	if other.Id != 0 {
		p.DNSMetrics.Id = other.Id
	}
	if p.DNSMetrics.Errno != other.Errno {
		p.DNSMetrics.Errno = other.Errno
	}
	if p.DNSMetrics.Latency < other.Latency {
		p.DNSMetrics.Latency = other.Latency
	}
}

func (p *BpfFlowContent) AccumulateDrops(other *ebpf.FlowsBpfPktDropMetrics) {
	if other == nil {
		return
	}
	p.buildBaseFromAdditional(other.StartMonoTimeTs, other.EndMonoTimeTs, other.EthProtocol)
	if p.PktDropMetrics == nil {
		p.PktDropMetrics = other
		return
	}
	// Drop statistics
	p.PktDropMetrics.Bytes = addUint16(p.PktDropMetrics.Bytes, other.Bytes)
	p.PktDropMetrics.Packets = addUint16(p.PktDropMetrics.Packets, other.Packets)
	p.PktDropMetrics.LatestFlags |= other.LatestFlags
	if other.LatestDropCause != 0 {
		p.PktDropMetrics.LatestDropCause = other.LatestDropCause
	}
	if other.LatestState != 0 {
		p.PktDropMetrics.LatestState = other.LatestState
	}
}

func (p *BpfFlowContent) AccumulateNetworkEvents(other *ebpf.FlowsBpfNetworkEventsMetrics) {
	if other == nil {
		return
	}
	p.buildBaseFromAdditional(other.StartMonoTimeTs, other.EndMonoTimeTs, other.EthProtocol)
	if p.NetworkEventsMetrics == nil {
		p.NetworkEventsMetrics = other
		return
	}
	// Network events
	for i, md := range other.NetworkEvents {
		if other.Packets[i] != 0 && !networkEventsMDExist(p.NetworkEventsMetrics.NetworkEvents, md) {
			p.NetworkEventsMetrics.Bytes[p.NetworkEventsMetrics.NetworkEventsIdx] = addUint16(p.NetworkEventsMetrics.Bytes[p.NetworkEventsMetrics.NetworkEventsIdx], other.Bytes[i])
			p.NetworkEventsMetrics.Packets[p.NetworkEventsMetrics.NetworkEventsIdx] = addUint16(p.NetworkEventsMetrics.Packets[p.NetworkEventsMetrics.NetworkEventsIdx], other.Packets[i])
			copy(p.NetworkEventsMetrics.NetworkEvents[p.NetworkEventsMetrics.NetworkEventsIdx][:], md[:])
			p.NetworkEventsMetrics.NetworkEventsIdx = (p.NetworkEventsMetrics.NetworkEventsIdx + 1) % MaxNetworkEvents
		}
	}
}

func (p *BpfFlowContent) AccumulateXlat(other *ebpf.FlowsBpfXlatMetrics) {
	if other == nil {
		return
	}
	p.buildBaseFromAdditional(other.StartMonoTimeTs, other.EndMonoTimeTs, other.EthProtocol)
	if p.XlatMetrics == nil {
		p.XlatMetrics = other
		return
	}
	// Packet Translations
	if !AllZeroIP(IP(other.Saddr)) && !AllZeroIP(IP(other.Daddr)) {
		p.XlatMetrics = other
	}
}

func (p *BpfFlowContent) AccumulateAdditional(other *ebpf.FlowsBpfAdditionalMetrics) {
	if other == nil {
		return
	}
	p.buildBaseFromAdditional(other.StartMonoTimeTs, other.EndMonoTimeTs, other.EthProtocol)
	if p.AdditionalMetrics == nil {
		p.AdditionalMetrics = other
		return
	}
	// RTT
	if p.AdditionalMetrics.FlowRtt < other.FlowRtt {
		p.AdditionalMetrics.FlowRtt = other.FlowRtt
	}
	// IPSec
	if p.AdditionalMetrics.IpsecEncryptedRet < other.IpsecEncryptedRet {
		p.AdditionalMetrics.IpsecEncrypted = other.IpsecEncrypted
		p.AdditionalMetrics.IpsecEncryptedRet = other.IpsecEncryptedRet
	}
	if p.AdditionalMetrics.IpsecEncryptedRet == other.IpsecEncryptedRet {
		if other.IpsecEncrypted {
			p.AdditionalMetrics.IpsecEncrypted = other.IpsecEncrypted
		}
	}
}

func (p *BpfFlowContent) AccumulateQuic(other *ebpf.FlowsBpfQuicMetrics) {
	if other == nil {
		return
	}
	p.buildBaseFromAdditional(other.StartMonoTimeTs, other.EndMonoTimeTs, other.EthProtocol)
	if p.QuicMetrics == nil {
		p.QuicMetrics = other
		return
	}
	// QUIC
	if p.QuicMetrics.Version < other.Version {
		p.QuicMetrics.Version = other.Version
	}
	if p.QuicMetrics.SeenLongHdr < other.SeenLongHdr {
		p.QuicMetrics.SeenLongHdr = other.SeenLongHdr
	}
	if p.QuicMetrics.SeenShortHdr < other.SeenShortHdr {
		p.QuicMetrics.SeenShortHdr = other.SeenShortHdr
	}
}

func AllZerosMac(s [6]uint8) bool {
	for _, v := range s {
		if v != 0 {
			return false
		}
	}
	return true
}

func addUint16(a, b uint16) uint16 {
	s := a + b
	if s < a {
		return math.MaxUint16
	}
	return s
}
