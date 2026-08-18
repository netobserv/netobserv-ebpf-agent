package decode

import (
	decodeflows "github.com/netobserv/netobserv-ebpf-agent/pkg/decode/flows"
	decodepackets "github.com/netobserv/netobserv-ebpf-agent/pkg/decode/packets"
)

// Flow decode types and helpers — re-exported from pkg/decode/flows for backward compatibility.
// New code should import github.com/netobserv/netobserv-ebpf-agent/pkg/decode/flows directly.

type Protobuf = decodeflows.Protobuf

var NewProtobuf = decodeflows.NewProtobuf

var (
	PBFlowToMap       = decodeflows.PBFlowToMap
	RecordToMap       = decodeflows.RecordToMap
	TCPStateToStr     = decodeflows.TCPStateToStr
	PktDropCauseToStr = decodeflows.PktDropCauseToStr
	DNSRcodeToStr     = decodeflows.DNSRcodeToStr

	// Packet decode helpers — re-exported from pkg/decode/packets.
	PacketToMap = decodepackets.PacketToMap
)
