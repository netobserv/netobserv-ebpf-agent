package flow

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

func TestPacketAggregation(t *testing.T) {
	type testCase struct {
		input    ebpf.BpfFlowMetrics
		expected ebpf.BpfFlowMetrics
	}
	tcs := []testCase{{
		input: ebpf.BpfFlowMetrics{Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1},
		expected: ebpf.BpfFlowMetrics{
			Packets: 0x7, Bytes: 0x22d, StartMonoTimeTs: 0x176a790b240b, EndMonoTimeTs: 0x176a792a755b, Flags: 1,
		},
	}, {
		input: ebpf.BpfFlowMetrics{Packets: 0x5, Bytes: 0x5c4, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1},
		expected: ebpf.BpfFlowMetrics{
			Packets: 0x5, Bytes: 0x5c4, StartMonoTimeTs: 0x17f3e9613a7f, EndMonoTimeTs: 0x17f3e979816e, Flags: 1,
		},
	}}
	for i, tc := range tcs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			assert.Equal(t,
				tc.expected,
				tc.input)
		})
	}
}
