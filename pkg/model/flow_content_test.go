package model

import (
	"testing"

	"github.com/stretchr/testify/assert"

	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
)

func TestAccumulateDNS(t *testing.T) {
	flow := BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
	}}

	flow.AccumulateDNS(&ebpf.FlowsBpfDnsMetrics{
		StartMonoTimeTs: 25,
		EndMonoTimeTs:   25,
		Latency:         1000,
		Id:              1,
		Flags:           0b00000011,
	})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 25, Packets: 3},
		DNSMetrics: &ebpf.FlowsBpfDnsMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			Latency:         1000,
			Id:              1,
			Flags:           0b00000011,
		},
	}, flow)

	flow.AccumulateDNS(&ebpf.FlowsBpfDnsMetrics{
		StartMonoTimeTs: 30,
		EndMonoTimeTs:   30,
		Latency:         2000,
		Id:              1,
		Flags:           0b00001001,
	})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		DNSMetrics: &ebpf.FlowsBpfDnsMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			Latency:         2000,
			Id:              1,
			Flags:           0b00001011,
		},
	}, flow)
}

func TestAccumulatePktDrops(t *testing.T) {
	flow := BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
	}}
	flow.AccumulateDrops(&ebpf.FlowsBpfPktDropMetrics{
		StartMonoTimeTs: 25,
		EndMonoTimeTs:   25,
		Bytes:           5,
		Packets:         1,
		LatestDropCause: 100,
		LatestFlags:     0b00000011,
		LatestState:     200,
	})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 25, Packets: 3},
		PktDropMetrics: &ebpf.FlowsBpfPktDropMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			Bytes:           5,
			Packets:         1,
			LatestDropCause: 100,
			LatestFlags:     0b00000011,
			LatestState:     200,
		},
	}, flow)

	flow.AccumulateDrops(&ebpf.FlowsBpfPktDropMetrics{
		StartMonoTimeTs: 30,
		EndMonoTimeTs:   30,
		Bytes:           10,
		Packets:         2,
		LatestDropCause: 101,
		LatestFlags:     0b00001001,
		LatestState:     201,
	})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		PktDropMetrics: &ebpf.FlowsBpfPktDropMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			Bytes:           15,
			Packets:         3,
			LatestDropCause: 101,
			LatestFlags:     0b00001011,
			LatestState:     201,
		},
	}, flow)
}

func TestAccumulateNetEvents(t *testing.T) {
	flow := BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
	}}
	flow.AccumulateNetworkEvents(&ebpf.FlowsBpfNetworkEventsMetrics{
		StartMonoTimeTs:  25,
		EndMonoTimeTs:    25,
		NetworkEventsIdx: 2,
		NetworkEvents:    [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{{1, 1, 0, 0, 0, 0, 0, 0}, {1, 2, 0, 0, 0, 0, 0, 0}},
		Bytes:            [MaxNetworkEvents]uint16{20, 25},
		Packets:          [MaxNetworkEvents]uint16{1, 2},
	})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 25, Packets: 3},
		NetworkEventsMetrics: &ebpf.FlowsBpfNetworkEventsMetrics{
			StartMonoTimeTs:  25,
			EndMonoTimeTs:    25,
			NetworkEventsIdx: 2,
			NetworkEvents:    [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{{1, 1, 0, 0, 0, 0, 0, 0}, {1, 2, 0, 0, 0, 0, 0, 0}},
			Bytes:            [MaxNetworkEvents]uint16{20, 25},
			Packets:          [MaxNetworkEvents]uint16{1, 2},
		},
	}, flow)

	flow.AccumulateNetworkEvents(&ebpf.FlowsBpfNetworkEventsMetrics{
		StartMonoTimeTs:  30,
		EndMonoTimeTs:    30,
		NetworkEventsIdx: 2,
		NetworkEvents:    [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{{1, 2, 0, 0, 0, 0, 0, 0}, {1, 3, 0, 0, 0, 0, 0, 0}},
		Bytes:            [MaxNetworkEvents]uint16{11, 12},
		Packets:          [MaxNetworkEvents]uint16{1, 1},
	})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		NetworkEventsMetrics: &ebpf.FlowsBpfNetworkEventsMetrics{
			StartMonoTimeTs:  25,
			EndMonoTimeTs:    25,
			NetworkEventsIdx: 3,
			NetworkEvents:    [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{{1, 1, 0, 0, 0, 0, 0, 0}, {1, 2, 0, 0, 0, 0, 0, 0}, {1, 3, 0, 0, 0, 0, 0, 0}},
			Bytes:            [MaxNetworkEvents]uint16{20, 25, 12},
			Packets:          [MaxNetworkEvents]uint16{1, 2, 1},
		},
	}, flow)
}

func TestAccumulateXlat(t *testing.T) {
	flow := BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
	}}
	flow.AccumulateXlat(&ebpf.FlowsBpfXlatMetrics{
		StartMonoTimeTs: 25,
		EndMonoTimeTs:   25,
	})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 25, Packets: 3},
		XlatMetrics: &ebpf.FlowsBpfXlatMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
		},
	}, flow)

	flow.AccumulateXlat(&ebpf.FlowsBpfXlatMetrics{
		StartMonoTimeTs: 30,
		EndMonoTimeTs:   30,
	})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		XlatMetrics: &ebpf.FlowsBpfXlatMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
		},
	}, flow)
}

func TestAccumulateAdditional(t *testing.T) {
	flow := BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
	}}
	flow.AccumulateAdditional(&ebpf.FlowsBpfAdditionalMetrics{
		StartMonoTimeTs: 25,
		EndMonoTimeTs:   25,
		FlowRtt:         200,
		IpsecEncrypted:  true,
	})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 25, Packets: 3},
		AdditionalMetrics: &ebpf.FlowsBpfAdditionalMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			FlowRtt:         200,
			IpsecEncrypted:  true,
		},
	}, flow)

	// Higher RTT, no ipsec info
	flow.AccumulateAdditional(&ebpf.FlowsBpfAdditionalMetrics{StartMonoTimeTs: 30, EndMonoTimeTs: 30, FlowRtt: 1000})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		AdditionalMetrics: &ebpf.FlowsBpfAdditionalMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			FlowRtt:         1000,
			IpsecEncrypted:  true,
		},
	}, flow)

	// Lower RTT, ipsec failure
	flow.AccumulateAdditional(&ebpf.FlowsBpfAdditionalMetrics{
		StartMonoTimeTs:   30,
		EndMonoTimeTs:     30,
		FlowRtt:           800,
		IpsecEncryptedRet: 5,
	})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		AdditionalMetrics: &ebpf.FlowsBpfAdditionalMetrics{
			StartMonoTimeTs:   25,
			EndMonoTimeTs:     25,
			FlowRtt:           1000,
			IpsecEncryptedRet: 5,
		},
	}, flow)

	// No change / empty ipsec
	flow.AccumulateAdditional(&ebpf.FlowsBpfAdditionalMetrics{StartMonoTimeTs: 30, EndMonoTimeTs: 30, FlowRtt: 800})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		AdditionalMetrics: &ebpf.FlowsBpfAdditionalMetrics{
			StartMonoTimeTs:   25,
			EndMonoTimeTs:     25,
			FlowRtt:           1000,
			IpsecEncryptedRet: 5,
		},
	}, flow)
}

func TestAccumulateQuic(t *testing.T) {
	flow := BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
	}}

	// First QUIC metric should set base timestamps and initialize QuicMetrics.
	flow.AccumulateQuic(&ebpf.FlowsBpfQuicMetrics{
		StartMonoTimeTs: 25,
		EndMonoTimeTs:   25,
		EthProtocol:     3,
		Version:         1,
		SeenLongHdr:     1,
		SeenShortHdr:    0,
	})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 25, Packets: 3, EthProtocol: 3},
		QuicMetrics: &ebpf.FlowsBpfQuicMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			EthProtocol:     3,
			Version:         1,
			SeenLongHdr:     1,
			SeenShortHdr:    0,
		},
	}, flow)

	// Second QUIC metric should update max fields.
	flow.AccumulateQuic(&ebpf.FlowsBpfQuicMetrics{
		StartMonoTimeTs: 30,
		EndMonoTimeTs:   30,
		EthProtocol:     3,
		Version:         2,
		SeenLongHdr:     0,
		SeenShortHdr:    1,
	})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3, EthProtocol: 3},
		QuicMetrics: &ebpf.FlowsBpfQuicMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			EthProtocol:     3,
			Version:         2,
			SeenLongHdr:     1,
			SeenShortHdr:    1,
		},
	}, flow)
}

func TestAccumulateQuic_NilNoop(t *testing.T) {
	flow := BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
		EthProtocol:     2048,
	}}
	before := flow
	flow.AccumulateQuic(nil)
	assert.Equal(t, before, flow)
}

func TestAccumulateQuic_DoesNotDecrease(t *testing.T) {
	flow := BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
		EthProtocol:     2048,
	}}
	flow.AccumulateQuic(&ebpf.FlowsBpfQuicMetrics{
		StartMonoTimeTs: 25,
		EndMonoTimeTs:   25,
		EthProtocol:     2048,
		Version:         2,
		SeenLongHdr:     1,
		SeenShortHdr:    1,
	})
	flow.AccumulateQuic(&ebpf.FlowsBpfQuicMetrics{
		StartMonoTimeTs: 30,
		EndMonoTimeTs:   30,
		EthProtocol:     2048,
		Version:         1, // lower than existing
		SeenLongHdr:     0,
		SeenShortHdr:    0,
	})
	assert.Equal(t, uint32(2), flow.QuicMetrics.Version)
	assert.Equal(t, uint8(1), flow.QuicMetrics.SeenLongHdr)
	assert.Equal(t, uint8(1), flow.QuicMetrics.SeenShortHdr)
}

func TestAccumulateNowBase(t *testing.T) {
	flow := BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{}}
	flow.AccumulateDNS(&ebpf.FlowsBpfDnsMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
		DNSMetrics:          &ebpf.FlowsBpfDnsMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
	}, flow)

	flow = BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{}}
	flow.AccumulateDrops(&ebpf.FlowsBpfPktDropMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
		PktDropMetrics:      &ebpf.FlowsBpfPktDropMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
	}, flow)

	flow = BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{}}
	flow.AccumulateNetworkEvents(&ebpf.FlowsBpfNetworkEventsMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics:  &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
		NetworkEventsMetrics: &ebpf.FlowsBpfNetworkEventsMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
	}, flow)

	flow = BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{}}
	flow.AccumulateXlat(&ebpf.FlowsBpfXlatMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
		XlatMetrics:         &ebpf.FlowsBpfXlatMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
	}, flow)

	flow = BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{}}
	flow.AccumulateAdditional(&ebpf.FlowsBpfAdditionalMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
		AdditionalMetrics:   &ebpf.FlowsBpfAdditionalMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
	}, flow)

	flow = BpfFlowContent{FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{}}
	flow.AccumulateQuic(&ebpf.FlowsBpfQuicMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25, EthProtocol: 3})
	assert.Equal(t, BpfFlowContent{
		FlowsBpfFlowMetrics: &ebpf.FlowsBpfFlowMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25, EthProtocol: 3},
		QuicMetrics:         &ebpf.FlowsBpfQuicMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25, EthProtocol: 3},
	}, flow)
}
