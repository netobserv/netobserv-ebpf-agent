package tracer

import (
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

const (
	protoESP    = 50
	protoUDP    = 17
	udpPortNATT = 4500
)

// mergeIPsecOrphans attaches IPsec metadata from zero-byte "partial" flows onto the
// corresponding on-wire flows (ESP, or UDP/4500 for NAT-T).
//
// xfrm_output sees the inner packet (often Geneve/UDP) while TC on host interfaces sees
// the encrypted form. When those flow_ids diverge, IPsec metrics land in orphan entries
// with 0 bytes/packets (NETOBSERV-2343). Prefer correlating by IP endpoints rather than
// dropping orphans entirely (partial flows remain useful for metrics when no sibling exists).
func mergeIPsecOrphans(flows map[ebpf.BpfFlowId]model.BpfFlowContent) {
	if len(flows) == 0 {
		return
	}

	type ipKey struct {
		src, dst [16]uint8
	}
	wireFlows := make(map[ipKey][]ebpf.BpfFlowId, len(flows))
	var orphans []ebpf.BpfFlowId

	for id, flow := range flows {
		if isIPsecOrphan(flow) {
			orphans = append(orphans, id)
			continue
		}
		if flow.BpfFlowMetrics == nil || flow.Packets == 0 {
			continue
		}
		if !isIPsecWireFlow(id) {
			continue
		}
		k := ipKey{src: id.SrcIp, dst: id.DstIp}
		wireFlows[k] = append(wireFlows[k], id)
	}

	for _, orphanID := range orphans {
		orphan, ok := flows[orphanID]
		if !ok || orphan.AdditionalMetrics == nil {
			continue
		}
		targets := wireFlows[ipKey{src: orphanID.SrcIp, dst: orphanID.DstIp}]
		if len(targets) == 0 {
			// Direction may differ between xfrm and TC observation points.
			targets = wireFlows[ipKey{src: orphanID.DstIp, dst: orphanID.SrcIp}]
		}
		if len(targets) == 0 {
			continue
		}

		targetID := targets[0]
		target := flows[targetID]
		target.AccumulateAdditional(orphan.AdditionalMetrics)
		flows[targetID] = target
		delete(flows, orphanID)
	}
}

func isIPsecOrphan(flow model.BpfFlowContent) bool {
	if flow.BpfFlowMetrics == nil || flow.AdditionalMetrics == nil {
		return false
	}
	if flow.Packets != 0 || flow.Bytes != 0 {
		return false
	}
	return flow.AdditionalMetrics.IpsecEncrypted || flow.AdditionalMetrics.IpsecEncryptedRet != 0
}

func isIPsecWireFlow(id ebpf.BpfFlowId) bool {
	if id.TransportProtocol == protoESP {
		return true
	}
	return id.TransportProtocol == protoUDP && (id.SrcPort == udpPortNATT || id.DstPort == udpPortNATT)
}
