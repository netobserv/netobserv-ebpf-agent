package model

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

var (
	additionalSample1 = ebpf.BpfAdditionalMetrics{
		DnsRecord: ebpf.BpfDnsRecordT{
			Latency: 100,
			Id:      101,
		},
		FlowRtt: 200,
		PktDrops: ebpf.BpfPktDropsT{
			Bytes:           10,
			Packets:         2,
			LatestDropCause: 5,
			LatestFlags:     6,
			LatestState:     7,
		},
	}
	additionalSample2 = ebpf.BpfAdditionalMetrics{
		DnsRecord: ebpf.BpfDnsRecordT{
			Latency: 1000,
			Id:      1000,
		},
		FlowRtt: 1000,
		PktDrops: ebpf.BpfPktDropsT{
			Bytes:           1000,
			Packets:         1000,
			LatestDropCause: 1000,
			LatestFlags:     1000,
			LatestState:     10,
		},
	}
)

func TestAccumulate(t *testing.T) {
	type testCase struct {
		name            string
		inputFlow       ebpf.BpfFlowMetrics
		inputAdditional []ebpf.BpfAdditionalMetrics
		expected        BpfFlowContent
	}
	tcs := []testCase{{
		name:      "flow without additional",
		inputFlow: ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		expected: BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{
			Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1,
		}},
	}, {
		name:            "with single additional",
		inputFlow:       ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		inputAdditional: []ebpf.BpfAdditionalMetrics{additionalSample1},
		expected: BpfFlowContent{
			BpfFlowMetrics:    &ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
			AdditionalMetrics: &additionalSample1,
		},
	}, {
		name:            "with two additional",
		inputFlow:       ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		inputAdditional: []ebpf.BpfAdditionalMetrics{additionalSample1, additionalSample2},
		expected: BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				DnsRecord: ebpf.BpfDnsRecordT{
					Latency: 1000, // keep highest
					Id:      1000, // last seen
				},
				FlowRtt: 1000, // keep highest
				PktDrops: ebpf.BpfPktDropsT{
					Bytes:           1010, // sum
					Packets:         1002, // sum
					LatestDropCause: 1000, // last seen
					LatestFlags:     1006, // union
					LatestState:     10,   // last seen
				},
			},
		},
	}, {
		name:      "duplicate net events",
		inputFlow: ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		inputAdditional: []ebpf.BpfAdditionalMetrics{
			{
				NetworkEventsIdx: 1,
				NetworkEvents: [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
				},
			},
			{
				NetworkEventsIdx: 1,
				NetworkEvents: [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
				},
			},
		},
		expected: BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				NetworkEventsIdx: 1,
				NetworkEvents: [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
				},
			}},
	}, {
		name:      "net events + empty net event",
		inputFlow: ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		inputAdditional: []ebpf.BpfAdditionalMetrics{
			{
				NetworkEventsIdx: 1,
				NetworkEvents: [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
				},
			},
			{
				NetworkEventsIdx: 0,
				NetworkEvents:    [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{},
			},
		},
		expected: BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				NetworkEventsIdx: 1,
				NetworkEvents: [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
				},
			}},
	}, {
		name:      "different net events",
		inputFlow: ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		inputAdditional: []ebpf.BpfAdditionalMetrics{
			{
				NetworkEventsIdx: 1,
				NetworkEvents: [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
				},
			},
			{
				NetworkEventsIdx: 1,
				NetworkEvents: [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{
					{1, 4, 0, 0, 0, 0, 0, 0},
				},
			},
		},
		expected: BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				NetworkEventsIdx: 2,
				NetworkEvents: [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
					{1, 4, 0, 0, 0, 0, 0, 0},
				},
			},
		},
	}, {
		name:      "3 different net events",
		inputFlow: ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		inputAdditional: []ebpf.BpfAdditionalMetrics{
			{
				NetworkEventsIdx: 2,
				NetworkEvents: [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
					{1, 3, 0, 0, 0, 0, 0, 0},
				},
			},
			{
				NetworkEventsIdx: 1,
				NetworkEvents: [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{
					{1, 4, 0, 0, 0, 0, 0, 0},
				},
			},
		},
		expected: BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				NetworkEventsIdx: 3,
				NetworkEvents: [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
					{1, 3, 0, 0, 0, 0, 0, 0},
					{1, 4, 0, 0, 0, 0, 0, 0},
				},
			},
		},
	}, {
		name:      "accumulate no base",
		inputFlow: ebpf.BpfFlowMetrics{},
		inputAdditional: []ebpf.BpfAdditionalMetrics{
			{DnsRecord: ebpf.BpfDnsRecordT{Id: 5}, StartMonoTimeTs: 15, EndMonoTimeTs: 25},
			{FlowRtt: 500},
			{PktDrops: ebpf.BpfPktDropsT{Packets: 5, Bytes: 1000, LatestFlags: 1}},
		},
		expected: BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 15, EndMonoTimeTs: 25, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				StartMonoTimeTs: 15,
				EndMonoTimeTs:   25,
				DnsRecord:       ebpf.BpfDnsRecordT{Id: 5},
				FlowRtt:         500,
				PktDrops:        ebpf.BpfPktDropsT{Packets: 5, Bytes: 1000, LatestFlags: 1},
			},
		},
	}, {
		name:      "IPsec: missing + success",
		inputFlow: ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		inputAdditional: []ebpf.BpfAdditionalMetrics{
			{
				FlowEncrypted:    false,
				FlowEncryptedRet: 0,
			},
			{
				FlowEncrypted:    true,
				FlowEncryptedRet: 0,
			},
		},
		expected: BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				FlowEncrypted:    true,
				FlowEncryptedRet: 0,
			},
		},
	}, {
		name:      "IPsec: success + missing",
		inputFlow: ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		inputAdditional: []ebpf.BpfAdditionalMetrics{
			{
				FlowEncrypted:    true,
				FlowEncryptedRet: 0,
			},
			{
				FlowEncrypted:    false,
				FlowEncryptedRet: 0,
			},
		},
		expected: BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				FlowEncrypted:    true,
				FlowEncryptedRet: 0,
			},
		},
	}, {
		name:      "IPsec: missing + error",
		inputFlow: ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		inputAdditional: []ebpf.BpfAdditionalMetrics{
			{
				FlowEncrypted:    false,
				FlowEncryptedRet: 0,
			},
			{
				FlowEncrypted:    false,
				FlowEncryptedRet: 2,
			},
		},
		expected: BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				FlowEncrypted:    false,
				FlowEncryptedRet: 2,
			},
		},
	}, {
		name:      "IPsec: error + missing",
		inputFlow: ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		inputAdditional: []ebpf.BpfAdditionalMetrics{
			{
				FlowEncrypted:    false,
				FlowEncryptedRet: 2,
			},
			{
				FlowEncrypted:    false,
				FlowEncryptedRet: 0,
			},
		},
		expected: BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				FlowEncrypted:    false,
				FlowEncryptedRet: 2,
			},
		},
	}, {
		name:      "IPsec: success + error",
		inputFlow: ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		inputAdditional: []ebpf.BpfAdditionalMetrics{
			{
				FlowEncrypted:    true,
				FlowEncryptedRet: 0,
			},
			{
				FlowEncrypted:    false,
				FlowEncryptedRet: 2,
			},
		},
		expected: BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				FlowEncrypted:    false,
				FlowEncryptedRet: 2,
			},
		},
	}, {
		name:      "IPsec: error + success",
		inputFlow: ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		inputAdditional: []ebpf.BpfAdditionalMetrics{
			{
				FlowEncrypted:    false,
				FlowEncryptedRet: 2,
			},
			{
				FlowEncrypted:    true,
				FlowEncryptedRet: 0,
			},
		},
		expected: BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				FlowEncrypted:    false,
				FlowEncryptedRet: 2,
			},
		},
	}}
	for i, tc := range tcs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			aggregated := BpfFlowContent{BpfFlowMetrics: &tc.inputFlow}
			for _, add := range tc.inputAdditional {
				aggregated.AccumulateAdditional(&add)
			}
			assert.Equalf(t, tc.expected, aggregated, "Test name: %s", tc.name)
		})
	}
}
