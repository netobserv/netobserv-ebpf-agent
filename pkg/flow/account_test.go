package flow

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const timeout = 5 * time.Second

var k1 = key{
	Transport: Transport{SrcPort: 333, DstPort: 8080},
	Network:   Network{SrcAddr: 0x12345678, DstAddr: 0x432100ff},
}
var k2 = key{
	Transport: Transport{SrcPort: 12, DstPort: 8080},
	Network:   Network{SrcAddr: 0xaabbccdd, DstAddr: 0x432100ff},
}
var k3 = key{
	Transport: Transport{SrcPort: 333, DstPort: 443},
	Network:   Network{SrcAddr: 0x12345678, DstAddr: 0x11223344},
}

func TestEvict_MaxEntries(t *testing.T) {
	// GIVEN an accounter
	acc := NewAccounter(2, 20, time.Hour)

	// WHEN it starts accounting new records
	inputs := make(chan *Record, 20)
	evictor := make(chan []*Record, 20)

	go acc.Account(inputs, evictor)

	// THEN It does not evict anything until it surpasses the maximum size
	// or the eviction period is reached
	requireNoEviction(t, evictor)
	inputs <- &Record{rawRecord: rawRecord{key: k1, Bytes: 123}, Packets: 1}
	inputs <- &Record{rawRecord: rawRecord{key: k2, Bytes: 456}, Packets: 1}
	inputs <- &Record{rawRecord: rawRecord{key: k1, Bytes: 321}, Packets: 1}
	requireNoEviction(t, evictor)

	// WHEN a new record surpasses the maximum number of records
	inputs <- &Record{rawRecord: rawRecord{key: k3, Bytes: 111}, Packets: 1}

	// THEN the old records are evicted
	received := map[key]Record{}
	r := receiveTimeout(t, evictor)
	require.Len(t, r, 2)
	received[r[0].key] = *r[0]
	received[r[1].key] = *r[1]

	requireNoEviction(t, evictor)

	// AND the returned records summarize the number of bytes and packages
	// of each flow
	assert.Equal(t, map[key]Record{
		k1: {rawRecord: rawRecord{key: k1, Bytes: 444}, Packets: 2},
		k2: {rawRecord: rawRecord{key: k2, Bytes: 456}, Packets: 1},
	}, received)
}

func TestEvict_Period(t *testing.T) {
	// GIVEN an accounter
	acc := NewAccounter(200, 20, 5*time.Millisecond)

	// WHEN it starts accounting new records
	inputs := make(chan *Record, 20)
	evictor := make(chan []*Record, 20)
	go acc.Account(inputs, evictor)

	inputs <- &Record{rawRecord: rawRecord{key: k1, Bytes: 10}, Packets: 1}
	inputs <- &Record{rawRecord: rawRecord{key: k1, Bytes: 10}, Packets: 1}
	inputs <- &Record{rawRecord: rawRecord{key: k1, Bytes: 10}, Packets: 1}
	// Forcing at least one eviction here
	time.Sleep(10 * time.Millisecond)
	inputs <- &Record{rawRecord: rawRecord{key: k1, Bytes: 10}, Packets: 1}
	inputs <- &Record{rawRecord: rawRecord{key: k1, Bytes: 10}, Packets: 1}

	// THEN it evicts them periodically if the size of the accounter
	// has not reached the maximum size
	timeout := time.After(timeout)
	sum := Record{rawRecord: rawRecord{key: k1}}
	numberOfEvictions := 0
	for sum.Packets != 5 {
		select {
		case rs := <-evictor:
			for _, r := range rs {
				sum.Accumulate(r)
			}
			numberOfEvictions++
		case <-timeout:
			require.Failf(t, "timeout while waiting for 5 evicted messages", "Got: %d", sum.Packets)
		}
	}
	assert.Equal(t, Record{rawRecord: rawRecord{key: k1, Bytes: 50}, Packets: 5}, sum)
	assert.GreaterOrEqual(t, numberOfEvictions, 2)
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
