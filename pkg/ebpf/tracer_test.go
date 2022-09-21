package ebpf

import (
	"fmt"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/stretchr/testify/assert"
)

func TestPacketAggregation(t *testing.T) {
	type testCase struct {
		input    []flow.RecordMetrics
		expected flow.RecordMetrics
	}
	tcs := []testCase{{
		input: []flow.RecordMetrics{
			{Packets: 0, Bytes: 0, StartMonoTimeNs: 0, EndMonoTimeNs: 0},
			{Packets: 0x7, Bytes: 0x22d, StartMonoTimeNs: 0x176a790b240b, EndMonoTimeNs: 0x176a792a755b},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeNs: 0x0, EndMonoTimeNs: 0x0},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeNs: 0x0, EndMonoTimeNs: 0x0},
		},
		expected: flow.RecordMetrics{
			Packets: 0x7, Bytes: 0x22d, StartMonoTimeNs: 0x176a790b240b, EndMonoTimeNs: 0x176a792a755b,
		},
	}, {
		input: []flow.RecordMetrics{
			{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeNs: 0x17f3e9613a7f, EndMonoTimeNs: 0x17f3e979816e},
			{Packets: 0x2, Bytes: 0x8c, StartMonoTimeNs: 0x17f3e9633a7f, EndMonoTimeNs: 0x17f3e96f164e},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeNs: 0x0, EndMonoTimeNs: 0x0},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeNs: 0x0, EndMonoTimeNs: 0x0},
		},
		expected: flow.RecordMetrics{
			Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeNs: 0x17f3e9613a7f, EndMonoTimeNs: 0x17f3e979816e,
		},
	}}
	ft := FlowTracer{}
	for i, tc := range tcs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			assert.Equal(t,
				tc.expected,
				ft.aggregate(tc.input))
		})
	}
}
