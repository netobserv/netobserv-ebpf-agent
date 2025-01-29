package exporter

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/utils"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/decode"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestConversions(t *testing.T) {
	decoder := decode.Protobuf{}

	someTime := time.Now()
	var someDuration time.Duration = 10000000 // 10ms

	tests := []struct {
		name     string
		flow     *model.Record
		expected *config.GenericMap
	}{
		{
			name: "TCP record",
			flow: &model.Record{
				ID: ebpf.BpfFlowId{
					SrcIp:             model.IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x06, 0x07, 0x08, 0x09},
					DstIp:             model.IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d},
					SrcPort:           23000,
					DstPort:           443,
					TransportProtocol: 6,
				},
				Metrics: model.BpfFlowContent{
					BpfFlowMetrics: &ebpf.BpfFlowMetrics{
						EthProtocol: 2048,
						SrcMac:      model.MacAddr{0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
						DstMac:      model.MacAddr{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
						Bytes:       456,
						Packets:     123,
						Flags:       0x100,
						Dscp:        64,
						Sampling:    1,
					},
					AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
						DnsRecord: ebpf.BpfDnsRecordT{
							Errno: 0,
						},
						FlowEncrypted: true,
					},
				},
				Interfaces:    []model.IntfDirUdn{model.NewIntfDirUdn("eth0", model.DirectionEgress, nil)},
				TimeFlowStart: someTime,
				TimeFlowEnd:   someTime,
				AgentIP:       net.IPv4(0x0a, 0x0b, 0x0c, 0x0d),
			},
			expected: &config.GenericMap{
				"IfDirections":    []int{1},
				"Bytes":           456,
				"SrcAddr":         "6.7.8.9",
				"DstAddr":         "10.11.12.13",
				"Dscp":            64,
				"DstMac":          "0A:0B:0C:0D:0E:0F",
				"SrcMac":          "04:05:06:07:08:09",
				"Etype":           2048,
				"Packets":         123,
				"Proto":           6,
				"SrcPort":         23000,
				"DstPort":         443,
				"Flags":           0x100,
				"Sampling":        1,
				"TimeFlowStartMs": someTime.UnixMilli(),
				"TimeFlowEndMs":   someTime.UnixMilli(),
				"Interfaces":      []string{"eth0"},
				"Udns":            []string{""},
				"AgentIP":         "10.11.12.13",
				"IPSecSuccess":    true,
				"IPSecRetCode":    0,
			},
		},
		{
			name: "UDP record",
			flow: &model.Record{
				ID: ebpf.BpfFlowId{
					SrcIp:             model.IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x06, 0x07, 0x08, 0x09},
					DstIp:             model.IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d},
					SrcPort:           23000,
					DstPort:           443,
					TransportProtocol: 17,
				},
				Metrics: model.BpfFlowContent{
					BpfFlowMetrics: &ebpf.BpfFlowMetrics{
						EthProtocol: 2048,
						SrcMac:      model.MacAddr{0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
						DstMac:      model.MacAddr{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
						Bytes:       456,
						Packets:     123,
						Dscp:        64,
						Sampling:    2,
					},
				},
				Interfaces:    []model.IntfDirUdn{model.NewIntfDirUdn("eth0", model.DirectionEgress, nil)},
				TimeFlowStart: someTime,
				TimeFlowEnd:   someTime,
				AgentIP:       net.IPv4(0x0a, 0x0b, 0x0c, 0x0d),
			},
			expected: &config.GenericMap{
				"IfDirections":    []int{1},
				"Bytes":           456,
				"SrcAddr":         "6.7.8.9",
				"DstAddr":         "10.11.12.13",
				"Dscp":            64,
				"DstMac":          "0A:0B:0C:0D:0E:0F",
				"SrcMac":          "04:05:06:07:08:09",
				"Etype":           2048,
				"Packets":         123,
				"Proto":           17,
				"Sampling":        2,
				"SrcPort":         23000,
				"DstPort":         443,
				"TimeFlowStartMs": someTime.UnixMilli(),
				"TimeFlowEndMs":   someTime.UnixMilli(),
				"Interfaces":      []string{"eth0"},
				"Udns":            []string{""},
				"AgentIP":         "10.11.12.13",
			},
		},
		{
			name: "ICMPv4 record",
			flow: &model.Record{
				ID: ebpf.BpfFlowId{
					SrcIp:             model.IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x06, 0x07, 0x08, 0x09},
					DstIp:             model.IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d},
					TransportProtocol: 1,
					IcmpType:          8,
					IcmpCode:          0,
				},
				Metrics: model.BpfFlowContent{
					BpfFlowMetrics: &ebpf.BpfFlowMetrics{
						EthProtocol: 2048,
						SrcMac:      model.MacAddr{0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
						DstMac:      model.MacAddr{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
						Bytes:       456,
						Packets:     123,
						Dscp:        64,
					},
				},
				Interfaces:    []model.IntfDirUdn{model.NewIntfDirUdn("eth0", model.DirectionEgress, nil)},
				TimeFlowStart: someTime,
				TimeFlowEnd:   someTime,
				AgentIP:       net.IPv4(0x0a, 0x0b, 0x0c, 0x0d),
			},
			expected: &config.GenericMap{
				"IfDirections":    []int{1},
				"Bytes":           456,
				"SrcAddr":         "6.7.8.9",
				"DstAddr":         "10.11.12.13",
				"Dscp":            64,
				"DstMac":          "0A:0B:0C:0D:0E:0F",
				"SrcMac":          "04:05:06:07:08:09",
				"Etype":           2048,
				"Packets":         123,
				"Proto":           1,
				"TimeFlowStartMs": someTime.UnixMilli(),
				"TimeFlowEndMs":   someTime.UnixMilli(),
				"Interfaces":      []string{"eth0"},
				"Udns":            []string{""},
				"AgentIP":         "10.11.12.13",
				"IcmpType":        8,
				"IcmpCode":        0,
			},
		},
		{
			name: "ICMPv6 record",
			flow: &model.Record{
				ID: ebpf.BpfFlowId{
					SrcIp:             model.IPAddr{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					DstIp:             model.IPAddr{11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26},
					TransportProtocol: 58,
					IcmpType:          8,
					IcmpCode:          0,
				},
				Metrics: model.BpfFlowContent{
					BpfFlowMetrics: &ebpf.BpfFlowMetrics{
						EthProtocol: 0x86dd,
						SrcMac:      model.MacAddr{0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
						DstMac:      model.MacAddr{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
						Bytes:       456,
						Packets:     123,
						Dscp:        64,
					},
				},
				Interfaces:    []model.IntfDirUdn{model.NewIntfDirUdn("eth0", model.DirectionEgress, nil)},
				TimeFlowStart: someTime,
				TimeFlowEnd:   someTime,
				AgentIP:       net.IPv4(0x0a, 0x0b, 0x0c, 0x0d),
			},
			expected: &config.GenericMap{
				"IfDirections":    []int{1},
				"Bytes":           456,
				"SrcAddr":         "102:304:506:708:90a:b0c:d0e:f10",
				"DstAddr":         "b0c:d0e:f10:1112:1314:1516:1718:191a",
				"Dscp":            64,
				"DstMac":          "0A:0B:0C:0D:0E:0F",
				"SrcMac":          "04:05:06:07:08:09",
				"Etype":           int(0x86dd),
				"Packets":         123,
				"Proto":           58,
				"TimeFlowStartMs": someTime.UnixMilli(),
				"TimeFlowEndMs":   someTime.UnixMilli(),
				"Interfaces":      []string{"eth0"},
				"Udns":            []string{""},
				"AgentIP":         "10.11.12.13",
				"IcmpType":        8,
				"IcmpCode":        0,
			},
		},
		{
			name: "ARP layer2",
			flow: &model.Record{
				ID: ebpf.BpfFlowId{
					SrcIp:             model.IPAddr{},
					DstIp:             model.IPAddr{},
					SrcPort:           0,
					DstPort:           0,
					TransportProtocol: 0,
					IcmpType:          8,
					IcmpCode:          0,
				},
				Metrics: model.BpfFlowContent{
					BpfFlowMetrics: &ebpf.BpfFlowMetrics{
						EthProtocol: 2054, // ARP protocol
						SrcMac:      model.MacAddr{0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
						DstMac:      model.MacAddr{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
						Bytes:       500,
						Packets:     128,
					},
				},
				Interfaces:    []model.IntfDirUdn{model.NewIntfDirUdn("eth0", model.DirectionEgress, nil)},
				TimeFlowStart: someTime,
				TimeFlowEnd:   someTime,
				AgentIP:       net.IPv4(0x0a, 0x0b, 0x0c, 0x0d),
			},
			expected: &config.GenericMap{
				"IfDirections":    []int{1},
				"Bytes":           500,
				"DstMac":          "0A:0B:0C:0D:0E:0F",
				"SrcMac":          "04:05:06:07:08:09",
				"Etype":           2054,
				"Packets":         128,
				"TimeFlowStartMs": someTime.UnixMilli(),
				"TimeFlowEndMs":   someTime.UnixMilli(),
				"Interfaces":      []string{"eth0"},
				"Udns":            []string{""},
				"AgentIP":         "10.11.12.13",
			},
		},
		{
			name: "L2 drops",
			flow: &model.Record{
				ID: ebpf.BpfFlowId{
					SrcIp:             model.IPAddr{},
					DstIp:             model.IPAddr{},
					SrcPort:           0,
					DstPort:           0,
					TransportProtocol: 0,
				},
				Metrics: model.BpfFlowContent{
					BpfFlowMetrics: &ebpf.BpfFlowMetrics{
						EthProtocol: 2054, // ARP protocol
						SrcMac:      model.MacAddr{0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
						DstMac:      model.MacAddr{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
						Bytes:       500,
						Packets:     128,
					},
					AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
						PktDrops: ebpf.BpfPktDropsT{
							Packets:         10,
							Bytes:           100,
							LatestFlags:     0x200,
							LatestState:     0,
							LatestDropCause: 2,
						},
					},
				},
				Interfaces:    []model.IntfDirUdn{model.NewIntfDirUdn("eth0", model.DirectionEgress, nil)},
				TimeFlowStart: someTime,
				TimeFlowEnd:   someTime,
				AgentIP:       net.IPv4(0x0a, 0x0b, 0x0c, 0x0d),
			},
			expected: &config.GenericMap{
				"IfDirections":           []int{1},
				"Bytes":                  500,
				"DstMac":                 "0A:0B:0C:0D:0E:0F",
				"SrcMac":                 "04:05:06:07:08:09",
				"Etype":                  2054,
				"Packets":                128,
				"TimeFlowStartMs":        someTime.UnixMilli(),
				"TimeFlowEndMs":          someTime.UnixMilli(),
				"Interfaces":             []string{"eth0"},
				"Udns":                   []string{""},
				"AgentIP":                "10.11.12.13",
				"PktDropBytes":           100,
				"PktDropPackets":         10,
				"PktDropLatestFlags":     0x200,
				"PktDropLatestState":     "TCP_INVALID_STATE",
				"PktDropLatestDropCause": "SKB_DROP_REASON_NOT_SPECIFIED",
			},
		},
		{
			name: "TCP + drop + DNS + RTT record",
			flow: &model.Record{
				ID: ebpf.BpfFlowId{
					SrcIp:             model.IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x06, 0x07, 0x08, 0x09},
					DstIp:             model.IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d},
					SrcPort:           23000,
					DstPort:           443,
					TransportProtocol: 6,
				},
				Metrics: model.BpfFlowContent{
					BpfFlowMetrics: &ebpf.BpfFlowMetrics{
						EthProtocol: 2048,
						SrcMac:      model.MacAddr{0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
						DstMac:      model.MacAddr{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
						Bytes:       456,
						Packets:     123,
						Flags:       0x100,
						Dscp:        64,
					},
					AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
						DnsRecord: ebpf.BpfDnsRecordT{
							Latency: uint64(someDuration),
							Id:      1,
							Flags:   0x8001,
							Errno:   0,
						},
						PktDrops: ebpf.BpfPktDropsT{
							Packets:         10,
							Bytes:           100,
							LatestFlags:     0x200,
							LatestState:     6,
							LatestDropCause: 5,
						},
						FlowEncrypted: true,
					},
				},
				Interfaces:    []model.IntfDirUdn{model.NewIntfDirUdn("eth0", model.DirectionEgress, nil)},
				TimeFlowStart: someTime,
				TimeFlowEnd:   someTime,
				AgentIP:       net.IPv4(0x0a, 0x0b, 0x0c, 0x0d),
				DNSLatency:    someDuration,
				TimeFlowRtt:   someDuration,
			},
			expected: &config.GenericMap{
				"IfDirections":           []int{1},
				"Bytes":                  456,
				"SrcAddr":                "6.7.8.9",
				"DstAddr":                "10.11.12.13",
				"Dscp":                   64,
				"DstMac":                 "0A:0B:0C:0D:0E:0F",
				"SrcMac":                 "04:05:06:07:08:09",
				"Etype":                  2048,
				"Packets":                123,
				"Proto":                  6,
				"SrcPort":                23000,
				"DstPort":                443,
				"Flags":                  0x100,
				"TimeFlowStartMs":        someTime.UnixMilli(),
				"TimeFlowEndMs":          someTime.UnixMilli(),
				"Interfaces":             []string{"eth0"},
				"Udns":                   []string{""},
				"AgentIP":                "10.11.12.13",
				"PktDropBytes":           100,
				"PktDropPackets":         10,
				"PktDropLatestFlags":     0x200,
				"PktDropLatestState":     "TCP_CLOSE",
				"PktDropLatestDropCause": "SKB_DROP_REASON_TCP_CSUM",
				"DnsLatencyMs":           someDuration.Milliseconds(),
				"DnsId":                  1,
				"DnsFlags":               0x8001,
				"DnsFlagsResponseCode":   "FormErr",
				"TimeFlowRttNs":          someDuration.Nanoseconds(),
				"IPSecSuccess":           true,
				"IPSecRetCode":           0,
			},
		},
		{
			name: "Multiple interfaces record",
			flow: &model.Record{
				ID: ebpf.BpfFlowId{
					SrcIp:             model.IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x06, 0x07, 0x08, 0x09},
					DstIp:             model.IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d},
					SrcPort:           23000,
					DstPort:           443,
					TransportProtocol: 6,
				},
				Metrics: model.BpfFlowContent{
					BpfFlowMetrics: &ebpf.BpfFlowMetrics{
						EthProtocol: 2048,
						SrcMac:      model.MacAddr{0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
						DstMac:      model.MacAddr{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
						Bytes:       64,
						Packets:     1,
						Flags:       0x100,
						Dscp:        64,
					},
					AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
						DnsRecord: ebpf.BpfDnsRecordT{
							Errno: 0,
						},
						FlowEncrypted: true,
					},
				},
				Interfaces: []model.IntfDirUdn{
					model.NewIntfDirUdn("5e6e92caa1d51cf", model.DirectionIngress, nil),
					model.NewIntfDirUdn("eth0", model.DirectionEgress, nil),
				},
				TimeFlowStart: someTime,
				TimeFlowEnd:   someTime,
				AgentIP:       net.IPv4(0x0a, 0x0b, 0x0c, 0x0d),
			},
			expected: &config.GenericMap{
				"IfDirections":    []int{0, 1},
				"Bytes":           64,
				"SrcAddr":         "6.7.8.9",
				"DstAddr":         "10.11.12.13",
				"Dscp":            64,
				"DstMac":          "0A:0B:0C:0D:0E:0F",
				"SrcMac":          "04:05:06:07:08:09",
				"Etype":           2048,
				"Packets":         1,
				"Proto":           6,
				"SrcPort":         23000,
				"DstPort":         443,
				"Flags":           0x100,
				"TimeFlowStartMs": someTime.UnixMilli(),
				"TimeFlowEndMs":   someTime.UnixMilli(),
				"Interfaces":      []string{"5e6e92caa1d51cf", "eth0"},
				"Udns":            []string{"", ""},
				"AgentIP":         "10.11.12.13",
				"IPSecSuccess":    true,
				"IPSecRetCode":    0,
			},
		},
	}

	for _, tt := range tests {
		// Generate with direct conversion
		outDirect := decode.RecordToMap(tt.flow)
		assert.NotZero(t, outDirect["TimeReceived"], tt.name)
		delete(outDirect, "TimeReceived")

		// Generate the same using protobuf
		tmpPB := pbflow.FlowToPB(tt.flow)
		rawPB, err := proto.Marshal(tmpPB)
		require.NoError(t, err, tt.name)
		outPB, err := decoder.Decode(rawPB)
		require.NoError(t, err, tt.name)
		assert.NotZero(t, outPB["TimeReceived"], tt.name)
		delete(outPB, "TimeReceived")

		// Make sure they're both equal
		assert.Equalf(t, outPB, outDirect, "%s: direct conversion and protobuf conversion should be identical", tt.name)

		// Check versus expected map
		err = normalizeMap(outDirect)
		require.NoError(t, err, tt.name)
		assert.Equalf(t, *tt.expected, outDirect, tt.name)

		err = normalizeMap(outPB)
		require.NoError(t, err, tt.name)
		assert.Equalf(t, *tt.expected, outPB, tt.name)
	}
}

func normalizeMap(m config.GenericMap) error {
	for k, v := range m {
		switch v := v.(type) {
		case bool, string, int64, []string, []int:
			continue
		case []uint8:
			var conv []int
			for _, vv := range v {
				conv = append(conv, int(vv))
			}
			m[k] = conv
		default:
			conv, err := utils.ConvertToUint32(v)
			if err != nil {
				return fmt.Errorf("can't convert %v (%s - %T) as uint32", v, k, v)
			}
			m[k] = int(conv)
		}
	}
	return nil
}
