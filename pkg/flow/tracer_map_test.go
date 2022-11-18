package flow

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPacketAggregation(t *testing.T) {
	type testCase struct {
		input    []RecordMetrics
		expected RecordMetrics
	}
	tcs := []testCase{{
		input: []RecordMetrics{
			{Packets: 0, Bytes: 0, StartMonoTimeNs: 0, EndMonoTimeNs: 0, Flags: 1},
			{Packets: 0x7, Bytes: 0x22d, StartMonoTimeNs: 0x176a790b240b, EndMonoTimeNs: 0x176a792a755b, Flags: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeNs: 0x0, EndMonoTimeNs: 0x0, Flags: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeNs: 0x0, EndMonoTimeNs: 0x0, Flags: 1},
		},
		expected: RecordMetrics{
			Packets: 0x7, Bytes: 0x22d, StartMonoTimeNs: 0x176a790b240b, EndMonoTimeNs: 0x176a792a755b, Flags: 1,
		},
	}, {
		input: []RecordMetrics{
			{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeNs: 0x17f3e9613a7f, EndMonoTimeNs: 0x17f3e979816e, Flags: 1},
			{Packets: 0x2, Bytes: 0x8c, StartMonoTimeNs: 0x17f3e9633a7f, EndMonoTimeNs: 0x17f3e96f164e, Flags: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeNs: 0x0, EndMonoTimeNs: 0x0, Flags: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeNs: 0x0, EndMonoTimeNs: 0x0, Flags: 1},
		},
		expected: RecordMetrics{
			Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeNs: 0x17f3e9613a7f, EndMonoTimeNs: 0x17f3e979816e, Flags: 1,
		},
	}}
	ft := MapTracer{}
	for i, tc := range tcs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			assert.Equal(t,
				tc.expected,
				ft.aggregate(tc.input))
		})
	}
}
