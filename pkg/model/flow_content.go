package model

import (
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

type BpfFlowContent struct {
	*ebpf.BpfFlowMetrics
	DNSMetrics           *ebpf.BpfDnsMetrics
	PktDropMetrics       *ebpf.BpfPktDropMetrics
	NetworkEventsMetrics *ebpf.BpfNetworkEventsMetrics
	XlatMetrics          *ebpf.BpfXlatMetrics
	AdditionalMetrics    *ebpf.BpfAdditionalMetrics
	QuicMetrics          *ebpf.BpfQuicMetrics
}

// nolint:gocritic // hugeParam: metric is reported as heavy; but it needs to be copied anyway, we don't want a pointer here
func NewBpfFlowContent(metrics ebpf.BpfFlowMetrics) BpfFlowContent {
	return BpfFlowContent{BpfFlowMetrics: &metrics}
}

func (p *BpfFlowContent) AccumulateBase(other *ebpf.BpfFlowMetrics) {
	p.BpfFlowMetrics = AccumulateBase(p.BpfFlowMetrics, other)
}

func AccumulateBase(p *ebpf.BpfFlowMetrics, other *ebpf.BpfFlowMetrics) *ebpf.BpfFlowMetrics {
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
	if p.BpfFlowMetrics.StartMonoTimeTs == 0 || (p.BpfFlowMetrics.StartMonoTimeTs > start && start != 0) {
		p.BpfFlowMetrics.StartMonoTimeTs = start
	}
	if p.BpfFlowMetrics.EndMonoTimeTs == 0 || p.BpfFlowMetrics.EndMonoTimeTs < end {
		p.BpfFlowMetrics.EndMonoTimeTs = end
	}
	if p.BpfFlowMetrics.EthProtocol == 0 {
		p.BpfFlowMetrics.EthProtocol = ethProto
	}
}

func (p *BpfFlowContent) AccumulateDNS(other *ebpf.BpfDnsMetrics) {
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

func (p *BpfFlowContent) AccumulateDrops(other *ebpf.BpfPktDropMetrics) {
	if other == nil {
		return
	}
	p.buildBaseFromAdditional(other.StartMonoTimeTs, other.EndMonoTimeTs, other.EthProtocol)
	if p.PktDropMetrics == nil {
		p.PktDropMetrics = other
		return
	}
	// Drop statistics
	p.PktDropMetrics.Bytes += other.Bytes
	p.PktDropMetrics.Packets += other.Packets
	p.PktDropMetrics.LatestFlags |= other.LatestFlags
	if other.LatestDropCause != 0 {
		p.PktDropMetrics.LatestDropCause = other.LatestDropCause
	}
	if other.LatestState != 0 {
		p.PktDropMetrics.LatestState = other.LatestState
	}
}

func (p *BpfFlowContent) AccumulateNetworkEvents(other *ebpf.BpfNetworkEventsMetrics) {
	if other == nil {
		return
	}
	p.buildBaseFromAdditional(other.StartMonoTimeTs, other.EndMonoTimeTs, other.EthProtocol)
	if p.NetworkEventsMetrics == nil {
		p.NetworkEventsMetrics = other
		return
	}
	// Network events
	for _, md := range other.NetworkEvents {
		if !AllZerosMetaData(md) && !networkEventsMDExist(p.NetworkEventsMetrics.NetworkEvents, md) {
			copy(p.NetworkEventsMetrics.NetworkEvents[p.NetworkEventsMetrics.NetworkEventsIdx][:], md[:])
			p.NetworkEventsMetrics.NetworkEventsIdx = (p.NetworkEventsMetrics.NetworkEventsIdx + 1) % MaxNetworkEvents
		}
	}
}

func (p *BpfFlowContent) AccumulateXlat(other *ebpf.BpfXlatMetrics) {
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

func (p *BpfFlowContent) AccumulateAdditional(other *ebpf.BpfAdditionalMetrics) {
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

func (p *BpfFlowContent) AccumulateQuic(other *ebpf.BpfQuicMetrics) {
	if other == nil {
		return
	}
	p.buildBaseFromAdditional(other.StartMonoTimeTs, other.EndMonoTimeTs, other.EthProtocol)
	if p.QuicMetrics == nil {
		p.QuicMetrics = other
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
