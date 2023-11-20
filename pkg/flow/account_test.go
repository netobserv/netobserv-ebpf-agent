package flow

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

const timeout = 5 * time.Second

var (
	srcAddr1 = IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
		0x12, 0x34, 0x56, 0x78}
	srcAddr2 = IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
		0xaa, 0xbb, 0xcc, 0xdd}
	dstAddr1 = IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
		0x43, 0x21, 0x00, 0xff}
	dstAddr2 = IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
		0x11, 0x22, 0x33, 0x44}
)

var k1 = ebpf.BpfFlowId{
	SrcPort: 333,
	DstPort: 8080,
	SrcIp:   srcAddr1,
	DstIp:   dstAddr1,
}
var k2 = ebpf.BpfFlowId{
	SrcPort: 12,
	DstPort: 8080,
	SrcIp:   srcAddr2,
	DstIp:   dstAddr1,
}
var k3 = ebpf.BpfFlowId{
	SrcPort: 333,
	DstPort: 443,
	SrcIp:   srcAddr1,
	DstIp:   dstAddr2,
}

func TestEvict_MaxEntries(t *testing.T) {
	// GIVEN an accounter
	now := time.Date(2022, 8, 23, 16, 33, 22, 0, time.UTC)
	acc := NewAccounter(2, time.Hour, func() time.Time {
		return now
	}, func() time.Duration {
		return 1000
	})

	// WHEN it starts accounting new records
	inputs := make(chan *RawRecord, 20)
	evictor := make(chan []*Record, 20)

	go acc.Account(inputs, evictor)

	// THEN It does not evict anything until it surpasses the maximum size
	// or the eviction period is reached
	requireNoEviction(t, evictor)
	inputs <- &RawRecord{
		Id: k1,
		Metrics: ebpf.BpfFlowMetrics{
			Bytes: 123, Packets: 1, StartMonoTimeTs: 123, EndMonoTimeTs: 123, Flags: 1,
		},
	}
	inputs <- &RawRecord{
		Id: k2,
		Metrics: ebpf.BpfFlowMetrics{
			Bytes: 456, Packets: 1, StartMonoTimeTs: 456, EndMonoTimeTs: 456, Flags: 1,
		},
	}
	inputs <- &RawRecord{
		Id: k1,
		Metrics: ebpf.BpfFlowMetrics{
			Bytes: 321, Packets: 1, StartMonoTimeTs: 789, EndMonoTimeTs: 789, Flags: 1,
		},
	}
	requireNoEviction(t, evictor)

	// WHEN a new record surpasses the maximum number of records
	inputs <- &RawRecord{
		Id: k3,
		Metrics: ebpf.BpfFlowMetrics{
			Bytes: 111, Packets: 1, StartMonoTimeTs: 888, EndMonoTimeTs: 888, Flags: 1,
		},
	}

	// THEN the old records are evicted
	received := map[ebpf.BpfFlowId]Record{}
	r := receiveTimeout(t, evictor)
	require.Len(t, r, 2)
	received[r[0].Id] = *r[0]
	received[r[1].Id] = *r[1]

	requireNoEviction(t, evictor)

	// AND the returned records summarize the number of bytes and packages
	// of each flow
	assert.Equal(t, map[ebpf.BpfFlowId]Record{
		k1: {
			RawRecord: RawRecord{
				Id: k1,
				Metrics: ebpf.BpfFlowMetrics{
					Bytes: 444, Packets: 2, StartMonoTimeTs: 123, EndMonoTimeTs: 789, Flags: 1,
				},
			},
			TimeFlowStart: now.Add(-(1000 - 123) * time.Nanosecond),
			TimeFlowEnd:   now.Add(-(1000 - 789) * time.Nanosecond),
			DupList:       make([]map[string]uint8, 0),
		},
		k2: {
			RawRecord: RawRecord{
				Id: k2,
				Metrics: ebpf.BpfFlowMetrics{
					Bytes: 456, Packets: 1, StartMonoTimeTs: 456, EndMonoTimeTs: 456, Flags: 1,
				},
			},
			TimeFlowStart: now.Add(-(1000 - 456) * time.Nanosecond),
			TimeFlowEnd:   now.Add(-(1000 - 456) * time.Nanosecond),
			DupList:       make([]map[string]uint8, 0),
		},
	}, received)
}

func TestEvict_Period(t *testing.T) {
	// GIVEN an accounter
	now := time.Date(2022, 8, 23, 16, 33, 22, 0, time.UTC)
	acc := NewAccounter(200, 20*time.Millisecond, func() time.Time {
		return now
	}, func() time.Duration {
		return 1000
	})

	// WHEN it starts accounting new records
	inputs := make(chan *RawRecord, 20)
	evictor := make(chan []*Record, 20)
	go acc.Account(inputs, evictor)

	inputs <- &RawRecord{
		Id: k1,
		Metrics: ebpf.BpfFlowMetrics{
			Bytes: 10, Packets: 1, StartMonoTimeTs: 123, EndMonoTimeTs: 123, Flags: 1,
		},
	}
	inputs <- &RawRecord{
		Id: k1,
		Metrics: ebpf.BpfFlowMetrics{
			Bytes: 10, Packets: 1, StartMonoTimeTs: 456, EndMonoTimeTs: 456, Flags: 1,
		},
	}
	inputs <- &RawRecord{
		Id: k1,
		Metrics: ebpf.BpfFlowMetrics{
			Bytes: 10, Packets: 1, StartMonoTimeTs: 789, EndMonoTimeTs: 789, Flags: 1,
		},
	}
	// Forcing at least one eviction here
	time.Sleep(30 * time.Millisecond)
	inputs <- &RawRecord{
		Id: k1,
		Metrics: ebpf.BpfFlowMetrics{
			Bytes: 10, Packets: 1, StartMonoTimeTs: 1123, EndMonoTimeTs: 1123, Flags: 1,
		},
	}
	inputs <- &RawRecord{
		Id: k1,
		Metrics: ebpf.BpfFlowMetrics{
			Bytes: 10, Packets: 1, StartMonoTimeTs: 1456, EndMonoTimeTs: 1456, Flags: 1,
		},
	}

	// THEN it evicts them periodically if the size of the accounter
	// has not reached the maximum size
	records := receiveTimeout(t, evictor)
	require.Len(t, records, 1)
	assert.Equal(t, Record{
		RawRecord: RawRecord{
			Id: k1,
			Metrics: ebpf.BpfFlowMetrics{
				Bytes:           30,
				Packets:         3,
				StartMonoTimeTs: 123,
				EndMonoTimeTs:   789,
				Flags:           1,
			},
		},
		TimeFlowStart: now.Add(-1000 + 123),
		TimeFlowEnd:   now.Add(-1000 + 789),
		DupList:       make([]map[string]uint8, 0),
	}, *records[0])
	records = receiveTimeout(t, evictor)
	require.Len(t, records, 1)
	assert.Equal(t, Record{
		RawRecord: RawRecord{
			Id: k1,
			Metrics: ebpf.BpfFlowMetrics{
				Bytes:           20,
				Packets:         2,
				StartMonoTimeTs: 1123,
				EndMonoTimeTs:   1456,
				Flags:           1,
			},
		},
		TimeFlowStart: now.Add(-1000 + 1123),
		TimeFlowEnd:   now.Add(-1000 + 1456),
		DupList:       make([]map[string]uint8, 0),
	}, *records[0])

	// no more flows are evicted
	time.Sleep(30 * time.Millisecond)
	requireNoEviction(t, evictor)
}

func receiveTimeout(t *testing.T, evictor <-chan []*Record) []*Record {
	t.Helper()
	select {
	case r := <-evictor:
		return r
	case <-time.After(timeout):
		require.Fail(t, "timeout while waiting for evicted record")
	}
	return nil
}

func requireNoEviction(t *testing.T, evictor <-chan []*Record) {
	t.Helper()
	select {
	case r := <-evictor:
		require.Failf(t, "unexpected evicted record", "%+v", r)
	default:
		// ok!
	}
}
