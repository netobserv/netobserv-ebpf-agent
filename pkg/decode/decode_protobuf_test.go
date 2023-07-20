package decode

import (
	"testing"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDecodeProtobuf(t *testing.T) {
	decoder := Protobuf{}

	someTime := time.Now()
	var someDuration time.Duration = 10000000 // 10ms

	tests := []struct {
		name     string
		flow     *pbflow.Record
		expected *config.GenericMap
	}{
		{
			name: "decode TCP gRPC record to GenericMap",
			flow: &pbflow.Record{
				Interface:     "eth0",
				EthProtocol:   2048,
				Bytes:         456,
				Packets:       123,
				Direction:     pbflow.Direction_EGRESS,
				TimeFlowStart: timestamppb.New(someTime),
				TimeFlowEnd:   timestamppb.New(someTime),
				Network: &pbflow.Network{
					SrcAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x01020304},
					},
					DstAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x05060708},
					},
					Dscp: 64,
				},
				DataLink: &pbflow.DataLink{
					DstMac: 0x112233445566,
					SrcMac: 0x010203040506,
				},
				Transport: &pbflow.Transport{
					Protocol: 6,
					SrcPort:  23000,
					DstPort:  443,
				},
				AgentIp: &pbflow.IP{
					IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x0a090807},
				},
				Flags: 0x100,
			},
			expected: &config.GenericMap{
				"FlowDirection":   1,
				"Bytes":           uint64(456),
				"SrcAddr":         "1.2.3.4",
				"DstAddr":         "5.6.7.8",
				"Dscp":            uint32(64),
				"DstMac":          "11:22:33:44:55:66",
				"SrcMac":          "01:02:03:04:05:06",
				"Duplicate":       false,
				"Etype":           uint32(2048),
				"Packets":         uint64(123),
				"Proto":           uint32(6),
				"SrcPort":         uint32(23000),
				"DstPort":         uint32(443),
				"Flags":           uint32(0x100),
				"TimeFlowStartMs": someTime.UnixMilli(),
				"TimeFlowEndMs":   someTime.UnixMilli(),
				"Interface":       "eth0",
				"AgentIP":         "10.9.8.7",
			},
		},
		{
			name: "decode UDP gRPC record to GenericMap",
			flow: &pbflow.Record{
				Interface:     "eth0",
				EthProtocol:   2048,
				Bytes:         456,
				Packets:       123,
				Direction:     pbflow.Direction_EGRESS,
				TimeFlowStart: timestamppb.New(someTime),
				TimeFlowEnd:   timestamppb.New(someTime),
				Network: &pbflow.Network{
					SrcAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x01020304},
					},
					DstAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x05060708},
					},
					Dscp: 64,
				},
				DataLink: &pbflow.DataLink{
					DstMac: 0x112233445566,
					SrcMac: 0x010203040506,
				},
				Transport: &pbflow.Transport{
					Protocol: 17,
					SrcPort:  23000,
					DstPort:  443,
				},
				AgentIp: &pbflow.IP{
					IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x0a090807},
				},
			},
			expected: &config.GenericMap{
				"FlowDirection":   1,
				"Bytes":           uint64(456),
				"SrcAddr":         "1.2.3.4",
				"DstAddr":         "5.6.7.8",
				"Dscp":            uint32(64),
				"DstMac":          "11:22:33:44:55:66",
				"SrcMac":          "01:02:03:04:05:06",
				"Duplicate":       false,
				"Etype":           uint32(2048),
				"Packets":         uint64(123),
				"Proto":           uint32(17),
				"SrcPort":         uint32(23000),
				"DstPort":         uint32(443),
				"TimeFlowStartMs": someTime.UnixMilli(),
				"TimeFlowEndMs":   someTime.UnixMilli(),
				"Interface":       "eth0",
				"AgentIP":         "10.9.8.7",
			},
		},
		{
			name: "decode ICMPv4 gRPC record to GenericMap",
			flow: &pbflow.Record{
				Interface:     "eth0",
				EthProtocol:   2048,
				Bytes:         456,
				Packets:       123,
				Direction:     pbflow.Direction_EGRESS,
				TimeFlowStart: timestamppb.New(someTime),
				TimeFlowEnd:   timestamppb.New(someTime),
				Network: &pbflow.Network{
					SrcAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x01020304},
					},
					DstAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x05060708},
					},
					Dscp: 64,
				},
				DataLink: &pbflow.DataLink{
					DstMac: 0x112233445566,
					SrcMac: 0x010203040506,
				},
				Transport: &pbflow.Transport{
					Protocol: 1,
				},
				AgentIp: &pbflow.IP{
					IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x0a090807},
				},
				IcmpType: 8,
				IcmpCode: 0,
			},
			expected: &config.GenericMap{
				"FlowDirection":   1,
				"Bytes":           uint64(456),
				"SrcAddr":         "1.2.3.4",
				"DstAddr":         "5.6.7.8",
				"Dscp":            uint32(64),
				"DstMac":          "11:22:33:44:55:66",
				"SrcMac":          "01:02:03:04:05:06",
				"Duplicate":       false,
				"Etype":           uint32(2048),
				"Packets":         uint64(123),
				"Proto":           uint32(1),
				"TimeFlowStartMs": someTime.UnixMilli(),
				"TimeFlowEndMs":   someTime.UnixMilli(),
				"Interface":       "eth0",
				"AgentIP":         "10.9.8.7",
				"IcmpType":        uint32(8),
				"IcmpCode":        uint32(0),
			},
		},
		{
			name: "decode ICMPv6 gRPC record to GenericMap",
			flow: &pbflow.Record{
				Interface:     "eth0",
				EthProtocol:   0x86dd,
				Bytes:         456,
				Packets:       123,
				Direction:     pbflow.Direction_EGRESS,
				TimeFlowStart: timestamppb.New(someTime),
				TimeFlowEnd:   timestamppb.New(someTime),
				Network: &pbflow.Network{
					SrcAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv6{Ipv6: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
					},
					DstAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv6{Ipv6: []byte{11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26}},
					},
					Dscp: 64,
				},
				DataLink: &pbflow.DataLink{
					DstMac: 0x112233445566,
					SrcMac: 0x010203040506,
				},
				Transport: &pbflow.Transport{
					Protocol: 58,
				},
				AgentIp: &pbflow.IP{
					IpFamily: &pbflow.IP_Ipv6{Ipv6: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}},
				},
				IcmpType: 128,
				IcmpCode: 0,
			},
			expected: &config.GenericMap{
				"FlowDirection":   1,
				"Bytes":           uint64(456),
				"SrcAddr":         "102:304:506:708:90a:b0c:d0e:f10",
				"DstAddr":         "b0c:d0e:f10:1112:1314:1516:1718:191a",
				"Dscp":            uint32(64),
				"DstMac":          "11:22:33:44:55:66",
				"SrcMac":          "01:02:03:04:05:06",
				"Duplicate":       false,
				"Etype":           uint32(0x86dd),
				"Packets":         uint64(123),
				"Proto":           uint32(58),
				"TimeFlowStartMs": someTime.UnixMilli(),
				"TimeFlowEndMs":   someTime.UnixMilli(),
				"Interface":       "eth0",
				"AgentIP":         "101:101:101:101:101:101:101:101",
				"IcmpType":        uint32(128),
				"IcmpCode":        uint32(0),
			},
		},
		{
			name: "decode ARP layer2 to GenericMap",
			flow: &pbflow.Record{
				Interface:     "eth0",
				EthProtocol:   2054, // ARP protocol
				Bytes:         500,
				Packets:       128,
				Direction:     pbflow.Direction_EGRESS,
				TimeFlowStart: timestamppb.New(someTime),
				TimeFlowEnd:   timestamppb.New(someTime),
				Network: &pbflow.Network{
					SrcAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x0},
					},
					DstAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x0},
					},
				},
				DataLink: &pbflow.DataLink{
					DstMac: 0x112233445566,
					SrcMac: 0x010203040506,
				},
				Transport: &pbflow.Transport{
					Protocol: 0,
					SrcPort:  0,
					DstPort:  0,
				},
				AgentIp: &pbflow.IP{
					IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x0a090807},
				},
			},
			expected: &config.GenericMap{
				"FlowDirection":   1,
				"Bytes":           uint64(500),
				"DstMac":          "11:22:33:44:55:66",
				"SrcMac":          "01:02:03:04:05:06",
				"Duplicate":       false,
				"Etype":           uint32(2054),
				"Packets":         uint64(128),
				"TimeFlowStartMs": someTime.UnixMilli(),
				"TimeFlowEndMs":   someTime.UnixMilli(),
				"Interface":       "eth0",
				"AgentIP":         "10.9.8.7",
			},
		},
		{
			name: "decode TCP + drop + DNS + RTT gRPC record to GenericMap",
			flow: &pbflow.Record{
				Interface:     "eth0",
				EthProtocol:   2048,
				Bytes:         456,
				Packets:       123,
				Direction:     pbflow.Direction_EGRESS,
				TimeFlowStart: timestamppb.New(someTime),
				TimeFlowEnd:   timestamppb.New(someTime),
				Network: &pbflow.Network{
					SrcAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x01020304},
					},
					DstAddr: &pbflow.IP{
						IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x05060708},
					},
					Dscp: 64,
				},
				DataLink: &pbflow.DataLink{
					DstMac: 0x112233445566,
					SrcMac: 0x010203040506,
				},
				Transport: &pbflow.Transport{
					Protocol: 6,
					SrcPort:  23000,
					DstPort:  443,
				},
				AgentIp: &pbflow.IP{
					IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x0a090807},
				},
				Flags:                  0x100,
				PktDropBytes:           100,
				PktDropPackets:         10,
				PktDropLatestFlags:     0x200,
				PktDropLatestState:     6,
				PktDropLatestDropCause: 5,
				DnsLatency:             durationpb.New(someDuration),
				DnsId:                  1,
				DnsFlags:               0x8001,
				TimeFlowRtt:            durationpb.New(someDuration),
			},
			expected: &config.GenericMap{
				"FlowDirection":          1,
				"Bytes":                  uint64(456),
				"SrcAddr":                "1.2.3.4",
				"DstAddr":                "5.6.7.8",
				"Dscp":                   uint32(64),
				"DstMac":                 "11:22:33:44:55:66",
				"SrcMac":                 "01:02:03:04:05:06",
				"Duplicate":              false,
				"Etype":                  uint32(2048),
				"Packets":                uint64(123),
				"Proto":                  uint32(6),
				"SrcPort":                uint32(23000),
				"DstPort":                uint32(443),
				"Flags":                  uint32(0x100),
				"TimeFlowStartMs":        someTime.UnixMilli(),
				"TimeFlowEndMs":          someTime.UnixMilli(),
				"Interface":              "eth0",
				"AgentIP":                "10.9.8.7",
				"PktDropBytes":           uint64(100),
				"PktDropPackets":         uint64(10),
				"PktDropLatestFlags":     uint32(0x200),
				"PktDropLatestState":     "TCP_CLOSE",
				"PktDropLatestDropCause": "SKB_DROP_REASON_TCP_CSUM",
				"DnsLatencyMs":           someDuration.Milliseconds(),
				"DnsId":                  uint32(1),
				"DnsFlags":               uint32(0x8001),
				"DnsFlagsResponseCode":   "FormErr",
				"TimeFlowRttNs":          someDuration.Nanoseconds(),
			},
		},
	}

	for _, tt := range tests {
		rawPB, err := proto.Marshal(tt.flow)
		require.NoError(t, err)
		out, err := decoder.Decode(rawPB)
		require.NoError(t, err)
		assert.NotZero(t, out["TimeReceived"])
		delete(out, "TimeReceived")
		assert.Equalf(t, *tt.expected, out, tt.name)
	}
}

func TestPBFlowToMap(t *testing.T) {
	someTime := time.Now()
	var someDuration time.Duration = 10000000 // 10ms
	flow := &pbflow.Record{
		Interface:     "eth0",
		EthProtocol:   2048,
		Bytes:         456,
		Packets:       123,
		Direction:     pbflow.Direction_EGRESS,
		TimeFlowStart: timestamppb.New(someTime),
		TimeFlowEnd:   timestamppb.New(someTime),
		Duplicate:     true,
		Network: &pbflow.Network{
			SrcAddr: &pbflow.IP{
				IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x01020304},
			},
			DstAddr: &pbflow.IP{
				IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x05060708},
			},
			Dscp: 64,
		},
		DataLink: &pbflow.DataLink{
			DstMac: 0x112233445566,
			SrcMac: 0x010203040506,
		},
		Transport: &pbflow.Transport{
			Protocol: 6,
			SrcPort:  23000,
			DstPort:  443,
		},
		AgentIp: &pbflow.IP{
			IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x0a090807},
		},
		Flags:                  0x100,
		PktDropBytes:           200,
		PktDropPackets:         20,
		PktDropLatestFlags:     0x100,
		PktDropLatestState:     1,
		PktDropLatestDropCause: 4,
		DnsLatency:             durationpb.New(someDuration),
		DnsId:                  1,
		DnsFlags:               0x80,
		TimeFlowRtt:            durationpb.New(someDuration),
	}

	out := PBFlowToMap(flow)
	assert.NotZero(t, out["TimeReceived"])
	delete(out, "TimeReceived")
	assert.Equal(t, config.GenericMap{
		"FlowDirection":          1,
		"Bytes":                  uint64(456),
		"SrcAddr":                "1.2.3.4",
		"DstAddr":                "5.6.7.8",
		"Dscp":                   uint32(64),
		"DstMac":                 "11:22:33:44:55:66",
		"SrcMac":                 "01:02:03:04:05:06",
		"SrcPort":                uint32(23000),
		"DstPort":                uint32(443),
		"Duplicate":              true,
		"Etype":                  uint32(2048),
		"Packets":                uint64(123),
		"Proto":                  uint32(6),
		"TimeFlowStartMs":        someTime.UnixMilli(),
		"TimeFlowEndMs":          someTime.UnixMilli(),
		"Interface":              "eth0",
		"AgentIP":                "10.9.8.7",
		"Flags":                  uint32(0x100),
		"PktDropBytes":           uint64(200),
		"PktDropPackets":         uint64(20),
		"PktDropLatestFlags":     uint32(0x100),
		"PktDropLatestState":     "TCP_ESTABLISHED",
		"PktDropLatestDropCause": "SKB_DROP_REASON_PKT_TOO_SMALL",
		"DnsLatencyMs":           someDuration.Milliseconds(),
		"DnsId":                  uint32(1),
		"DnsFlags":               uint32(0x80),
		"DnsFlagsResponseCode":   "NoError",
		"TimeFlowRttNs":          someDuration.Nanoseconds(),
	}, out)

}
