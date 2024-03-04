package flow

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

func TestPacketAggregation(t *testing.T) {
	type testCase struct {
		input    []ebpf.BpfFlowMetrics
		expected ebpf.BpfFlowMetrics
	}
	tcs := []testCase{{
		input: []ebpf.BpfFlowMetrics{
			{Packets: 0, Bytes: 0, StartMonoTimeTs: 0, EndMonoTimeTs: 0, Flags: 1},
			{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1},
		},
		expected: ebpf.BpfFlowMetrics{
			Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1,
		},
	}, {
		input: []ebpf.BpfFlowMetrics{
			{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1},
			{Packets: 0x2, Bytes: 0x8c, StartMonoTimeTs: 0x17f3e9633a7f, EndMonoTimeTs: 0x17f3e96f164e, Flags: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1},
		},
		expected: ebpf.BpfFlowMetrics{
			Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1,
		},
	}, {
		input: []ebpf.BpfFlowMetrics{
			{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1, NetworkEventsIdx: 1,
				NetworkEvents: [4][8]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
				},
			},
			{Packets: 0x2, Bytes: 0x8c, StartMonoTimeTs: 0x17f3e9633a7f, EndMonoTimeTs: 0x17f3e96f164e, Flags: 1, NetworkEventsIdx: 1,
				NetworkEvents: [4][8]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
				},
			},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1},
		},
		expected: ebpf.BpfFlowMetrics{
			Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1, NetworkEventsIdx: 1,
			NetworkEvents: [4][8]uint8{
				{1, 2, 0, 0, 0, 0, 0, 0},
			},
		},
	}, {
		input: []ebpf.BpfFlowMetrics{
			{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1, NetworkEventsIdx: 1,
				NetworkEvents: [4][8]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
				},
			},
			{Packets: 0x2, Bytes: 0x8c, StartMonoTimeTs: 0x17f3e9633a7f, EndMonoTimeTs: 0x17f3e96f164e, Flags: 1, NetworkEventsIdx: 0,
				NetworkEvents: [4][8]uint8{},
			},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1},
		},
		expected: ebpf.BpfFlowMetrics{
			Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1, NetworkEventsIdx: 1,
			NetworkEvents: [4][8]uint8{
				{1, 2, 0, 0, 0, 0, 0, 0},
			},
		},
	}, {
		input: []ebpf.BpfFlowMetrics{
			{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1, NetworkEventsIdx: 1,
				NetworkEvents: [4][8]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
				},
			},
			{Packets: 0x2, Bytes: 0x8c, StartMonoTimeTs: 0x17f3e9633a7f, EndMonoTimeTs: 0x17f3e96f164e, Flags: 1, NetworkEventsIdx: 1,
				NetworkEvents: [4][8]uint8{
					{1, 4, 0, 0, 0, 0, 0, 0},
				},
			},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1},
		},
		expected: ebpf.BpfFlowMetrics{
			Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1, NetworkEventsIdx: 2,
			NetworkEvents: [4][8]uint8{
				{1, 2, 0, 0, 0, 0, 0, 0},
				{1, 4, 0, 0, 0, 0, 0, 0},
			},
		},
	}, {
		input: []ebpf.BpfFlowMetrics{
			{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1, NetworkEventsIdx: 2,
				NetworkEvents: [4][8]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
					{1, 3, 0, 0, 0, 0, 0, 0},
				},
			},
			{Packets: 0x2, Bytes: 0x8c, StartMonoTimeTs: 0x17f3e9633a7f, EndMonoTimeTs: 0x17f3e96f164e, Flags: 1, NetworkEventsIdx: 1,
				NetworkEvents: [4][8]uint8{
					{1, 4, 0, 0, 0, 0, 0, 0},
				},
			},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1},
		},
		expected: ebpf.BpfFlowMetrics{
			Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1, NetworkEventsIdx: 3,
			NetworkEvents: [4][8]uint8{
				{1, 2, 0, 0, 0, 0, 0, 0},
				{1, 3, 0, 0, 0, 0, 0, 0},
				{1, 4, 0, 0, 0, 0, 0, 0},
			},
		},
	},
	}
	ft := MapTracer{}
	for i, tc := range tcs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			assert.Equal(t,
				tc.expected,
				*ft.aggregate(tc.input))
		})
	}
}
