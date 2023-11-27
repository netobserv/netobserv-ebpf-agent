package flow

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/utils"
)

var (
	// the same flow from 2 different interfaces
	oneIf1 = &Record{RawRecord: RawRecord{Id: ebpf.BpfFlowId{
		EthProtocol: 1, Direction: 1, SrcPort: 123, DstPort: 456,
		DstMac: MacAddr{0x1}, SrcMac: MacAddr{0x1}, IfIndex: 1,
	}, Metrics: ebpf.BpfFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
	}}, Interface: "eth0"}
	oneIf2 = &Record{RawRecord: RawRecord{Id: ebpf.BpfFlowId{
		EthProtocol: 1, Direction: 1, SrcPort: 123, DstPort: 456,
		DstMac: MacAddr{0x2}, SrcMac: MacAddr{0x2}, IfIndex: 2,
	}, Metrics: ebpf.BpfFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
	}}, Interface: "123456789"}
	// another flow from 2 different interfaces and directions
	twoIf1 = &Record{RawRecord: RawRecord{Id: ebpf.BpfFlowId{
		EthProtocol: 1, Direction: 1, SrcPort: 333, DstPort: 456,
		DstMac: MacAddr{0x1}, SrcMac: MacAddr{0x1}, IfIndex: 1,
	}, Metrics: ebpf.BpfFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
	}}, Interface: "eth0"}
	twoIf2 = &Record{RawRecord: RawRecord{Id: ebpf.BpfFlowId{
		EthProtocol: 1, Direction: 0, SrcPort: 333, DstPort: 456,
		DstMac: MacAddr{0x2}, SrcMac: MacAddr{0x2}, IfIndex: 2,
	}, Metrics: ebpf.BpfFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
	}}, Interface: "123456789"}
	// another flow from 2 different interfaces and directions with DNS latency set on the latest
	threeIf1 = &Record{RawRecord: RawRecord{Id: ebpf.BpfFlowId{
		EthProtocol: 1, Direction: 1, SrcPort: 433, DstPort: 456,
		DstMac: MacAddr{0x1}, SrcMac: MacAddr{0x1}, IfIndex: 1,
	}, Metrics: ebpf.BpfFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
	}}, Interface: "eth0"}
	threeIf2 = &Record{RawRecord: RawRecord{Id: ebpf.BpfFlowId{
		EthProtocol: 1, Direction: 0, SrcPort: 433, DstPort: 456,
		DstMac: MacAddr{0x2}, SrcMac: MacAddr{0x2}, IfIndex: 2,
	}, Metrics: ebpf.BpfFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
		DnsRecord: ebpf.BpfDnsRecordT{Id: 1, Flags: 100, Latency: 1000},
	}}, Interface: "123456789", DNSLatency: time.Millisecond}
)

func TestDedupe(t *testing.T) {
	input := make(chan []*Record, 100)
	output := make(chan []*Record, 100)

	go Dedupe(time.Minute, false, false)(input, output)

	input <- []*Record{
		oneIf2,   // record 1 at interface 2: should be accepted
		twoIf1,   // record 2 at interface 1: should be accepted
		oneIf1,   // record 1 duplicate at interface 1: should NOT be accepted
		oneIf1,   //                                        (same record key, different interface)
		twoIf2,   // record 2 duplicate at interface 2: should NOT be accepted
		oneIf2,   // record 1 at interface 1: should be accepted (same record key, same interface)
		threeIf1, // record 1 has no DNS so it get enriched with DNS record from the following record
		threeIf2, // record 2 is duplicate of record1 and have DNS info , should not be accepted
	}
	deduped := receiveTimeout(t, output)
	assert.Equal(t, []*Record{oneIf2, twoIf1, oneIf2, threeIf1}, deduped)

	// should still accept records with same key, same interface,
	// and discard these with same key, different interface
	input <- []*Record{oneIf1, oneIf2}
	deduped = receiveTimeout(t, output)
	assert.Equal(t, []*Record{oneIf2}, deduped)

	// make sure flow with no DNS get enriched with the DNS record
	assert.Equal(t, threeIf1.Metrics.DnsRecord.Id, threeIf2.Metrics.DnsRecord.Id)
	assert.Equal(t, threeIf1.Metrics.DnsRecord.Flags, threeIf2.Metrics.DnsRecord.Flags)
	assert.Equal(t, threeIf1.Metrics.DnsRecord.Latency, threeIf2.Metrics.DnsRecord.Latency)
}

func TestDedupe_EvictFlows(t *testing.T) {
	tm := &timerMock{now: time.Now()}
	timeNow = tm.Now
	input := make(chan []*Record, 100)
	output := make(chan []*Record, 100)

	go Dedupe(15*time.Second, false, false)(input, output)

	// Should only accept records 1 and 2, at interface 1
	input <- []*Record{oneIf1, twoIf1, oneIf2}
	assert.Equal(t, []*Record{oneIf1, twoIf1},
		receiveTimeout(t, output))

	tm.now = tm.now.Add(10 * time.Second)

	// After 10 seconds, it still filters existing flows from different interfaces
	input <- []*Record{oneIf2}
	time.Sleep(100 * time.Millisecond)
	requireNoEviction(t, output)

	tm.now = tm.now.Add(10 * time.Second)

	// Record 2 hasn't been accounted for >expiryTime, so it will accept the it again
	// whatever the interface.
	// Since record 1 was accessed 10 seconds ago (<expiry time) it will filter it
	input <- []*Record{oneIf2, twoIf2, twoIf1}
	assert.Equal(t, []*Record{twoIf2},
		receiveTimeout(t, output))

	tm.now = tm.now.Add(20 * time.Second)

	// when all the records expire, the deduper is reset for that flow
	input <- []*Record{oneIf2, twoIf2}
	assert.Equal(t, []*Record{oneIf2, twoIf2},
		receiveTimeout(t, output))
}

func TestDedupeMerge(t *testing.T) {
	input := make(chan []*Record, 100)
	output := make(chan []*Record, 100)

	go Dedupe(time.Minute, false, true)(input, output)

	input <- []*Record{
		oneIf2, // record 1 at interface 2: should be accepted
		oneIf1,
	}
	deduped := receiveTimeout(t, output)
	assert.Equal(t, []*Record{oneIf2}, deduped)
	assert.Equal(t, 2, len(oneIf2.DupList))

	expectedMap := []map[string]uint8{
		{
			utils.GetInterfaceName(oneIf2.Id.IfIndex): oneIf2.Id.Direction,
		},
		{
			utils.GetInterfaceName(oneIf1.Id.IfIndex): oneIf1.Id.Direction,
		},
	}

	for k, v := range oneIf2.DupList {
		assert.Equal(t, expectedMap[k], v)
	}
}

type timerMock struct {
	now time.Time
}

func (tm *timerMock) Now() time.Time {
	return tm.now
}
