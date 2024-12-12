package flow

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

func TestPacketAggregation(t *testing.T) {
	type testCase struct {
		name     string
		input    model.BpfFlowContents
		expected model.BpfFlowContent
	}
	tcs := []testCase{{
		name: "single valid entry and empty",
		input: []model.BpfFlowContent{
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0, Bytes: 0, StartMonoTimeTs: 0, EndMonoTimeTs: 0, Flags: 1}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1}},
		},
		expected: model.BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{
			Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1,
		}},
	}, {
		name: "two valid entries and empty",
		input: []model.BpfFlowContent{
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x2, Bytes: 0x8c, StartMonoTimeTs: 0x17f3e9633a7f, EndMonoTimeTs: 0x17f3e96f164e, Flags: 1}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1}},
		},
		expected: model.BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{
			Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1,
		}},
	}, {
		name: "duplicate net events",
		input: []model.BpfFlowContent{
			{
				BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1},
				AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
					NetworkEventsIdx: 1,
					NetworkEvents: [model.MaxNetworkEvents][model.NetworkEventsMaxEventsMD]uint8{
						{1, 2, 0, 0, 0, 0, 0, 0},
					},
				}},
			{
				BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x2, Bytes: 0x8c, StartMonoTimeTs: 0x17f3e9633a7f, EndMonoTimeTs: 0x17f3e96f164e, Flags: 1},
				AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
					NetworkEventsIdx: 1,
					NetworkEvents: [model.MaxNetworkEvents][model.NetworkEventsMaxEventsMD]uint8{
						{1, 2, 0, 0, 0, 0, 0, 0},
					},
				}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1}},
		},
		expected: model.BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				NetworkEventsIdx: 1,
				NetworkEvents: [model.MaxNetworkEvents][model.NetworkEventsMaxEventsMD]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
				},
			}},
	}, {
		name: "net events + empty net event",
		input: []model.BpfFlowContent{
			{
				BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1},
				AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
					NetworkEventsIdx: 1,
					NetworkEvents: [model.MaxNetworkEvents][model.NetworkEventsMaxEventsMD]uint8{
						{1, 2, 0, 0, 0, 0, 0, 0},
					},
				}},
			{
				BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x2, Bytes: 0x8c, StartMonoTimeTs: 0x17f3e9633a7f, EndMonoTimeTs: 0x17f3e96f164e, Flags: 1},
				AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
					NetworkEventsIdx: 0,
					NetworkEvents:    [model.MaxNetworkEvents][model.NetworkEventsMaxEventsMD]uint8{},
				}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1}},
		},
		expected: model.BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				NetworkEventsIdx: 1,
				NetworkEvents: [model.MaxNetworkEvents][model.NetworkEventsMaxEventsMD]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
				},
			}},
	}, {
		name: "different net events",
		input: []model.BpfFlowContent{
			{
				BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1},
				AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
					NetworkEventsIdx: 1,
					NetworkEvents: [model.MaxNetworkEvents][model.NetworkEventsMaxEventsMD]uint8{
						{1, 2, 0, 0, 0, 0, 0, 0},
					},
				}},
			{
				BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x2, Bytes: 0x8c, StartMonoTimeTs: 0x17f3e9633a7f, EndMonoTimeTs: 0x17f3e96f164e, Flags: 1},
				AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
					NetworkEventsIdx: 1,
					NetworkEvents: [model.MaxNetworkEvents][model.NetworkEventsMaxEventsMD]uint8{
						{1, 4, 0, 0, 0, 0, 0, 0},
					},
				}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1}},
		},
		expected: model.BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				NetworkEventsIdx: 2,
				NetworkEvents: [model.MaxNetworkEvents][model.NetworkEventsMaxEventsMD]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
					{1, 4, 0, 0, 0, 0, 0, 0},
				},
			}},
	}, {
		name: "3 different net events",
		input: []model.BpfFlowContent{
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1},
				AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
					NetworkEventsIdx: 2,
					NetworkEvents: [model.MaxNetworkEvents][model.NetworkEventsMaxEventsMD]uint8{
						{1, 2, 0, 0, 0, 0, 0, 0},
						{1, 3, 0, 0, 0, 0, 0, 0},
					},
				}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x2, Bytes: 0x8c, StartMonoTimeTs: 0x17f3e9633a7f, EndMonoTimeTs: 0x17f3e96f164e, Flags: 1},
				AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
					NetworkEventsIdx: 1,
					NetworkEvents: [model.MaxNetworkEvents][model.NetworkEventsMaxEventsMD]uint8{
						{1, 4, 0, 0, 0, 0, 0, 0},
					},
				}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1}},
			{BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x0, Bytes: 0x0, StartMonoTimeTs: 0x0, EndMonoTimeTs: 0x0, Flags: 1}},
		},
		expected: model.BpfFlowContent{
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1},
			AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
				NetworkEventsIdx: 3,
				NetworkEvents: [model.MaxNetworkEvents][model.NetworkEventsMaxEventsMD]uint8{
					{1, 2, 0, 0, 0, 0, 0, 0},
					{1, 3, 0, 0, 0, 0, 0, 0},
					{1, 4, 0, 0, 0, 0, 0, 0},
				},
			}},
	},
	}
	for i, tc := range tcs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			assert.Equalf(t, tc.expected, tc.input.Accumulate(), "Test name: %s", tc.name)
		})
	}
}
