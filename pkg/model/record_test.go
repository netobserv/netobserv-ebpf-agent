package model

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

func TestRecordBinaryEncoding(t *testing.T) {
	// Makes sure that we read the C *not packed* flow structure according
	// to the order defined in bpf/flow.h
	fr, err := ReadFrom(bytes.NewReader([]byte{
		// ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x06, 0x07, 0x08, 0x09, // network: u8[16] src_ip
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d, // network: u8[16] dst_ip
		0x0e, 0x0f, // transport: u16 src_port
		0x10, 0x11, // transport: u16 dst_port
		0x12, // transport: u8 transport_protocol
		0x00, // icmp: u8 icmp_type
		0x00, // icmp: u8 icmp_code
		0x00, // 1 byte padding
		// Metrics
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, // u64 flow_start_time
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, // u64 flow_end_time
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, // u64 bytes
		0x06, 0x07, 0x08, 0x09, // u32 packets
		0x01, 0x02, // u16 eth_protocol
		0x13, 0x14, // flags
		0x04, 0x05, 0x06, 0x07, 0x08, 0x09, // data_link: u8[6] src_mac
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // data_link: u8[6] dst_mac
		0x13, 0x14, 0x15, 0x16, // u32 if_index_first_seen
		0x00, 0x00, 0x00, 0x00, // u32 lock
		0x02, 0x00, 0x00, 0x00, // u32 sampling
		0x03,                         // u8 direction_first_seen
		0x33,                         // u8 errno
		0x60,                         // u8 dscp
		0x00, 0x00, 0x00, 0x00, 0x00, // 5 bytes padding
	}))
	require.NoError(t, err)

	assert.Equal(t, RawRecord{
		Id: ebpf.BpfFlowId{
			SrcIp:             IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x06, 0x07, 0x08, 0x09},
			DstIp:             IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d},
			SrcPort:           0x0f0e,
			DstPort:           0x1110,
			TransportProtocol: 0x12,
			IcmpType:          0x00,
			IcmpCode:          0x00,
		},
		Metrics: ebpf.BpfFlowMetrics{
			DirectionFirstSeen: 0x03,
			IfIndexFirstSeen:   0x16151413,
			EthProtocol:        0x0201,
			SrcMac:             MacAddr{0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
			DstMac:             MacAddr{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
			Packets:            0x09080706,
			Bytes:              0x1a19181716151413,
			StartMonoTimeTs:    0x1a19181716151413,
			EndMonoTimeTs:      0x1a19181716151413,
			Flags:              0x1413,
			Errno:              0x33,
			Dscp:               0x60,
			Sampling:           0x02,
		},
	}, *fr)
	// assert that IP addresses are interpreted as IPv4 addresses
	assert.Equal(t, "6.7.8.9", IP(fr.Id.SrcIp).String())
	assert.Equal(t, "10.11.12.13", IP(fr.Id.DstIp).String())
}

func TestAdditionalMetricsBinaryEncoding(t *testing.T) {
	// Makes sure that we read the C *not packed* additional metrics structure according
	// to the order defined in bpf/flow.h
	b := []byte{
		0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // u64 flow_start_time
		0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // u64 flow_end_time
		// dns_record structure
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // latency
		01, 00, // id
		0x80, 00, // flags
		0x00,             // errno
		0x00, 0x00, 0x00, // 3 bytes padding
		// pkt_drops structure
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, // u64 bytes
		0x10, 0x11, 0x12, 0x13, // u32 packets
		0x11, 0, 0, 0, // cause
		0x1c, 0x1d, // flags
		0x1e,                         // state
		0x00, 0x00, 0x00, 0x00, 0x00, // 5 bytes padding
		0xad, 0xde, 0xef, 0xbe, 0xef, 0xbe, 0xad, 0xde, // u64 flow_rtt
		// u8 network_events[4][8]
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// translated flow
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x02, 0x00,
		0x00, 0x00, // 2bytes padding
		// observed_intf_t[4]
		0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, // [0]: u8 direction + 3 bytes padding + u32 if_index
		0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // [1]: u8 direction + 3 bytes padding + u32 if_index
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [2]: u8 direction + 3 bytes padding + u32 if_index
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [3]: u8 direction + 3 bytes padding + u32 if_index
		0x03, 0x00, // u16 eth_protocol
		0x01,                   // u8 network_events_idx
		0x02,                   // u8 nb_observed_intf
		0x00, 0x00, 0x00, 0x00, // 4 bytes padding
	}
	var addmet ebpf.BpfAdditionalMetrics
	err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &addmet)
	require.NoError(t, err)

	assert.Equal(t, ebpf.BpfAdditionalMetrics{
		StartMonoTimeTs: 0x10,
		EndMonoTimeTs:   0xFF,
		EthProtocol:     3,
		PktDrops: ebpf.BpfPktDropsT{
			Packets:         0x13121110,
			Bytes:           0x1b1a191817161514,
			LatestFlags:     0x1d1c,
			LatestState:     0x1e,
			LatestDropCause: 0x11,
		},
		DnsRecord: ebpf.BpfDnsRecordT{
			Id:      0x0001,
			Flags:   0x0080,
			Latency: 0x1817161514131211,
			Errno:   0,
		},
		FlowRtt:          0xdeadbeefbeefdead,
		NetworkEventsIdx: 1,
		NetworkEvents: [4][8]uint8{
			{
				0x0,
			},
		},
		TranslatedFlow: ebpf.BpfTranslatedFlowT{
			Saddr:  IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Daddr:  IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Sport:  0,
			Dport:  0,
			ZoneId: 2,
		},
		NbObservedIntf: 2,
		ObservedIntf: [MaxObservedInterfaces]ebpf.BpfObservedIntfT{
			{Direction: 1, IfIndex: 7},
			{Direction: 0, IfIndex: 8},
		},
	}, addmet)
}
