package decode

import (
	"testing"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/utils"

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
		DnsName:                "www.example.com",
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
		IpsecEncrypted:    1,
		IpsecEncryptedRet: 0,
		Quic: &pbflow.Quic{
			Version:      1,
			SeenLongHdr:  1,
			SeenShortHdr: 1,
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
		"DnsName":                "www.example.com",
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
		"XlatSrcAddr":      "1.2.3.4",
		"XlatDstAddr":      "5.6.7.8",
		"XlatSrcPort":      uint16(1),
		"XlatDstPort":      uint16(2),
		"ZoneId":           uint16(100),
		"IPSecRetCode":     int32(0),
		"IPSecStatus":      "success",
		"QuicVersion":      uint32(1),
		"QuicSeenLongHdr":  uint8(1),
		"QuicSeenShortHdr": uint8(1),
	}, out)
}

func TestDnsRawNameToDotted(t *testing.T) {
	tests := []struct {
		name     string
		input    []int8
		expected string
	}{
		{
			name:     "empty input",
			input:    []int8{},
			expected: "",
		},
		{
			name:     "null terminated empty",
			input:    []int8{0},
			expected: "",
		},
		{
			name:     "simple single label",
			input:    []int8{3, 'a', 'b', 'c', 0},
			expected: "abc",
		},
		{
			name:     "multiple labels",
			input:    []int8{3, 'a', 'b', 'c', 3, 'd', 'e', 'f', 0},
			expected: "abc.def",
		},
		{
			name:     "root domain",
			input:    []int8{0},
			expected: "",
		},
		{
			name:     "realistic domain name",
			input:    []int8{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			expected: "www.example.com",
		},
		{
			name:     "compression pointer stops parsing",
			input:    []int8{3, 'a', 'b', 'c', -64, 0x12, 0}, // 0xC0 = -64 in int8
			expected: "abc",
		},
		{
			name:     "compression pointer at start",
			input:    []int8{-64, 0x12}, // 0xC0 = -64 in int8
			expected: "",
		},
		{
			name:     "length exceeds buffer",
			input:    []int8{10, 'a', 'b', 'c'},
			expected: "",
		},
		{
			name:     "zero length label",
			input:    []int8{0, 3, 'a', 'b', 'c', 0},
			expected: "",
		},
		{
			name:     "null terminator in middle",
			input:    []int8{3, 'a', 'b', 0, 3, 'd', 'e', 'f', 0},
			expected: "",
		},
		{
			name:     "single character labels",
			input:    []int8{1, 'a', 1, 'b', 1, 'c', 0},
			expected: "a.b.c",
		},
		{
			name:     "long label",
			input:    []int8{10, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 0},
			expected: "abcdefghij",
		},
		{
			name:     "mixed case",
			input:    []int8{3, 'A', 'b', 'C', 3, 'D', 'e', 'F', 0},
			expected: "AbC.DeF",
		},
		{
			name:     "numbers and special chars",
			input:    []int8{5, 't', 'e', 's', 't', '1', 3, 'a', 'b', 'c', 0},
			expected: "test1.abc",
		},
		{
			name:     "incomplete label at end",
			input:    []int8{3, 'a', 'b', 'c', 5, 'd', 'e'},
			expected: "abc",
		},
		{
			name:     "multiple compression pointers",
			input:    []int8{3, 'a', 'b', 'c', -64, 0x12, -64, 0x34, 0}, // 0xC0 = -64 in int8
			expected: "abc",
		},
		{
			name: "very long input with early null",
			input: func() []int8 {
				result := make([]int8, 1000)
				result[0] = 3
				result[1] = 'a'
				result[2] = 'b'
				result[3] = 'c'
				result[4] = 0
				return result
			}(),
			expected: "abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utils.DNSRawNameToDotted(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
