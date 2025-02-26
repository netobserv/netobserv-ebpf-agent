package decode

import (
	"testing"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NOTE: more tests in convert_flp_test.go

func TestPBFlowToMap(t *testing.T) {
	someTime := time.Now()
	var someDuration time.Duration = 10000000 // 10ms
	flow := &pbflow.Record{
		DupList: []*pbflow.DupMapEntry{
			{
				Interface: "5e6e92caa1d51cf",
				Direction: pbflow.Direction_INGRESS,
			},
			{
				Interface: "eth0",
				Direction: pbflow.Direction_EGRESS,
			},
		},
		EthProtocol:   2048,
		Bytes:         456,
		Packets:       123,
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
		PktDropBytes:           200,
		PktDropPackets:         20,
		PktDropLatestFlags:     0x100,
		PktDropLatestState:     1,
		PktDropLatestDropCause: 4,
		DnsLatency:             durationpb.New(someDuration),
		DnsId:                  1,
		DnsFlags:               0x80,
		DnsErrno:               0,
		TimeFlowRtt:            durationpb.New(someDuration),
		NetworkEventsMetadata: []*pbflow.NetworkEvent{
			{
				Events: map[string]string{
					"Name":      "test1",
					"Type":      "NetworkPolicy",
					"Feature":   "acl",
					"Namespace": "test-namespace",
					"Direction": "ingress",
				},
			},
			{
				Events: map[string]string{
					"Name":      "test2",
					"Type":      "NetworkPolicy",
					"Feature":   "acl",
					"Namespace": "test-namespace",
					"Direction": "egress",
				},
			},
		},
		Xlat: &pbflow.Xlat{
			SrcAddr: &pbflow.IP{
				IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x01020304},
			},
			DstAddr: &pbflow.IP{
				IpFamily: &pbflow.IP_Ipv4{Ipv4: 0x05060708},
			},
			SrcPort: 1,
			DstPort: 2,
			ZoneId:  100,
		},
	}

	out := PBFlowToMap(flow)
	assert.NotZero(t, out["TimeReceived"])
	delete(out, "TimeReceived")
	assert.Equal(t, config.GenericMap{
		"IfDirections":           []int{0, 1},
		"Bytes":                  uint64(456),
		"SrcAddr":                "1.2.3.4",
		"DstAddr":                "5.6.7.8",
		"Dscp":                   uint8(64),
		"DstMac":                 "11:22:33:44:55:66",
		"SrcMac":                 "01:02:03:04:05:06",
		"SrcPort":                uint16(23000),
		"DstPort":                uint16(443),
		"Etype":                  uint16(2048),
		"Packets":                uint32(123),
		"Proto":                  uint8(6),
		"TimeFlowStartMs":        someTime.UnixMilli(),
		"TimeFlowEndMs":          someTime.UnixMilli(),
		"Interfaces":             []string{"5e6e92caa1d51cf", "eth0"},
		"Udns":                   []string{"", ""},
		"AgentIP":                "10.9.8.7",
		"Flags":                  uint16(0x100),
		"PktDropBytes":           uint64(200),
		"PktDropPackets":         uint32(20),
		"PktDropLatestFlags":     uint16(0x100),
		"PktDropLatestState":     "TCP_ESTABLISHED",
		"PktDropLatestDropCause": "SKB_DROP_REASON_PKT_TOO_SMALL",
		"DnsLatencyMs":           someDuration.Milliseconds(),
		"DnsId":                  uint16(1),
		"DnsFlags":               uint16(0x80),
		"DnsFlagsResponseCode":   "NoError",
		"TimeFlowRttNs":          someDuration.Nanoseconds(),
		"NetworkEvents": []map[string]string{
			{
				"Name":      "test1",
				"Type":      "NetworkPolicy",
				"Feature":   "acl",
				"Namespace": "test-namespace",
				"Direction": "ingress",
			},
			{
				"Name":      "test2",
				"Type":      "NetworkPolicy",
				"Feature":   "acl",
				"Namespace": "test-namespace",
				"Direction": "egress",
			},
		},
		"XlatSrcAddr": "1.2.3.4",
		"XlatDstAddr": "5.6.7.8",
		"XlatSrcPort": uint16(1),
		"XlatDstPort": uint16(2),
		"ZoneId":      uint16(100),
	}, out)
}

func TestPBFlowToMapDropEvent(t *testing.T) {
	someTime := time.Now()
	flow := &pbflow.Record{
		EthProtocol:   2048,
		Bytes:         12,
		Packets:       34,
		TimeFlowStart: timestamppb.New(someTime),
		TimeFlowEnd:   timestamppb.New(someTime),
		Network:       &pbflow.Network{},
		Transport:     &pbflow.Transport{},
		NetworkEventsMetadata: []*pbflow.NetworkEvent{
			{
				Events: map[string]string{
					"Action":    "drop",
					"Actor":     "AdminNetworkPolicy",
					"Direction": "ingress",
					"Name":      "my-policy",
				},
			},
		},
	}

	out := PBFlowToMap(flow)
	assert.NotZero(t, out["TimeReceived"])
	delete(out, "TimeReceived")

	var nilIntArr []int
	var nilStrArr []string

	assert.Equal(t, config.GenericMap{
		"Bytes":                  uint64(12),
		"SrcAddr":                "0.0.0.0",
		"DstAddr":                "0.0.0.0",
		"Dscp":                   uint8(0),
		"DstMac":                 "00:00:00:00:00:00",
		"SrcMac":                 "00:00:00:00:00:00",
		"Packets":                uint32(34),
		"Proto":                  uint8(0),
		"TimeFlowStartMs":        someTime.UnixMilli(),
		"TimeFlowEndMs":          someTime.UnixMilli(),
		"AgentIP":                "0.0.0.0",
		"PktDropBytes":           uint64(12),
		"PktDropPackets":         uint32(34),
		"PktDropLatestDropCause": "OVS_DROP_EXPLICIT",
		"Etype":                  uint16(2048),
		"IfDirections":           nilIntArr,
		"Interfaces":             nilStrArr,
		"NetworkEvents": []map[string]string{
			{
				"Action":    "drop",
				"Actor":     "AdminNetworkPolicy",
				"Direction": "ingress",
				"Name":      "my-policy",
			},
		},
	}, out)
}
