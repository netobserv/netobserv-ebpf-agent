package decode

import (
	decodeflows "github.com/netobserv/netobserv-ebpf-agent/pkg/decode/flows"
	decodepackets "github.com/netobserv/netobserv-ebpf-agent/pkg/decode/packets"
)

// Deprecated: import pkg/decode/flows or pkg/decode/packets directly.
// Kept for flowlogs-pipeline v1.11.5-community compatibility until FLP is updated.

type Protobuf = decodeflows.Protobuf

var NewProtobuf = decodeflows.NewProtobuf

var (
	PBFlowToMap       = decodeflows.PBFlowToMap
	RecordToMap       = decodeflows.RecordToMap
	TCPStateToStr     = decodeflows.TCPStateToStr
	PktDropCauseToStr = decodeflows.PktDropCauseToStr
	DNSRcodeToStr     = decodeflows.DNSRcodeToStr

	PacketToMap = decodepackets.PacketToMap
)
