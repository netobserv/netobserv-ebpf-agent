package model

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

func TestAccumulateDNS(t *testing.T) {
	flow := BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
	}}

	flow.AccumulateDNS(&ebpf.BpfDnsMetrics{
		StartMonoTimeTs: 25,
		EndMonoTimeTs:   25,
		Latency:         1000,
		Id:              1,
		Flags:           0b00000011,
	})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 25, Packets: 3},
		DNSMetrics: &ebpf.BpfDnsMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			Latency:         1000,
			Id:              1,
			Flags:           0b00000011,
		},
	}, flow)

	flow.AccumulateDNS(&ebpf.BpfDnsMetrics{
		StartMonoTimeTs: 30,
		EndMonoTimeTs:   30,
		Latency:         2000,
		Id:              1,
		Flags:           0b00001001,
	})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		DNSMetrics: &ebpf.BpfDnsMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			Latency:         2000,
			Id:              1,
			Flags:           0b00001011,
		},
	}, flow)
}

func TestAccumulatePktDrops(t *testing.T) {
	flow := BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
	}}
	flow.AccumulateDrops(&ebpf.BpfPktDropMetrics{
		StartMonoTimeTs: 25,
		EndMonoTimeTs:   25,
		Bytes:           5,
		Packets:         1,
		LatestDropCause: 100,
		LatestFlags:     0b00000011,
		LatestState:     200,
	})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 25, Packets: 3},
		PktDropMetrics: &ebpf.BpfPktDropMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			Bytes:           5,
			Packets:         1,
			LatestDropCause: 100,
			LatestFlags:     0b00000011,
			LatestState:     200,
		},
	}, flow)

	flow.AccumulateDrops(&ebpf.BpfPktDropMetrics{
		StartMonoTimeTs: 30,
		EndMonoTimeTs:   30,
		Bytes:           10,
		Packets:         2,
		LatestDropCause: 101,
		LatestFlags:     0b00001001,
		LatestState:     201,
	})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		PktDropMetrics: &ebpf.BpfPktDropMetrics{
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
	flow := BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
	}}
	flow.AccumulateNetworkEvents(&ebpf.BpfNetworkEventsMetrics{
		StartMonoTimeTs:  25,
		EndMonoTimeTs:    25,
		NetworkEventsIdx: 2,
		NetworkEvents:    [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{{1, 1, 0, 0, 0, 0, 0, 0}, {1, 2, 0, 0, 0, 0, 0, 0}},
	})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 25, Packets: 3},
		NetworkEventsMetrics: &ebpf.BpfNetworkEventsMetrics{
			StartMonoTimeTs:  25,
			EndMonoTimeTs:    25,
			NetworkEventsIdx: 2,
			NetworkEvents:    [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{{1, 1, 0, 0, 0, 0, 0, 0}, {1, 2, 0, 0, 0, 0, 0, 0}},
		},
	}, flow)

	flow.AccumulateNetworkEvents(&ebpf.BpfNetworkEventsMetrics{
		StartMonoTimeTs:  30,
		EndMonoTimeTs:    30,
		NetworkEventsIdx: 2,
		NetworkEvents:    [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{{1, 2, 0, 0, 0, 0, 0, 0}, {1, 3, 0, 0, 0, 0, 0, 0}},
	})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		NetworkEventsMetrics: &ebpf.BpfNetworkEventsMetrics{
			StartMonoTimeTs:  25,
			EndMonoTimeTs:    25,
			NetworkEventsIdx: 3,
			NetworkEvents:    [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8{{1, 1, 0, 0, 0, 0, 0, 0}, {1, 2, 0, 0, 0, 0, 0, 0}, {1, 3, 0, 0, 0, 0, 0, 0}},
		},
	}, flow)
}

func TestAccumulateXlat(t *testing.T) {
	flow := BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
	}}
	flow.AccumulateXlat(&ebpf.BpfXlatMetrics{
		StartMonoTimeTs: 25,
		EndMonoTimeTs:   25,
	})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 25, Packets: 3},
		XlatMetrics: &ebpf.BpfXlatMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
		},
	}, flow)

	flow.AccumulateXlat(&ebpf.BpfXlatMetrics{
		StartMonoTimeTs: 30,
		EndMonoTimeTs:   30,
	})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		XlatMetrics: &ebpf.BpfXlatMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
		},
	}, flow)
}

func TestAccumulateAdditional(t *testing.T) {
	flow := BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
	}}
	flow.AccumulateAdditional(&ebpf.BpfAdditionalMetrics{
		StartMonoTimeTs: 25,
		EndMonoTimeTs:   25,
		FlowRtt:         200,
		IpsecEncrypted:  true,
	})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 25, Packets: 3},
		AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			FlowRtt:         200,
			IpsecEncrypted:  true,
		},
	}, flow)

	// Higher RTT, no ipsec info
	flow.AccumulateAdditional(&ebpf.BpfAdditionalMetrics{StartMonoTimeTs: 30, EndMonoTimeTs: 30, FlowRtt: 1000})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			FlowRtt:         1000,
			IpsecEncrypted:  true,
		},
	}, flow)

	// Lower RTT, ipsec failure
	flow.AccumulateAdditional(&ebpf.BpfAdditionalMetrics{
		StartMonoTimeTs:   30,
		EndMonoTimeTs:     30,
		FlowRtt:           800,
		IpsecEncryptedRet: 5,
	})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
			StartMonoTimeTs:   25,
			EndMonoTimeTs:     25,
			FlowRtt:           1000,
			IpsecEncryptedRet: 5,
		},
	}, flow)

	// No change / empty ipsec
	flow.AccumulateAdditional(&ebpf.BpfAdditionalMetrics{StartMonoTimeTs: 30, EndMonoTimeTs: 30, FlowRtt: 800})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3},
		AdditionalMetrics: &ebpf.BpfAdditionalMetrics{
			StartMonoTimeTs:   25,
			EndMonoTimeTs:     25,
			FlowRtt:           1000,
			IpsecEncryptedRet: 5,
		},
	}, flow)
}

func TestAccumulateQuic(t *testing.T) {
	flow := BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
	}}

	// First QUIC metric should set base timestamps and initialize QuicMetrics.
	flow.AccumulateQuic(&ebpf.BpfQuicMetrics{
		StartMonoTimeTs: 25,
		EndMonoTimeTs:   25,
		EthProtocol:     3,
		Version:         1,
		SeenLongHdr:     1,
		SeenShortHdr:    0,
	})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 25, Packets: 3, EthProtocol: 3},
		QuicMetrics: &ebpf.BpfQuicMetrics{
			StartMonoTimeTs: 25,
			EndMonoTimeTs:   25,
			EthProtocol:     3,
			Version:         1,
			SeenLongHdr:     1,
			SeenShortHdr:    0,
		},
	}, flow)

	// Second QUIC metric should update max fields.
	flow.AccumulateQuic(&ebpf.BpfQuicMetrics{
		StartMonoTimeTs: 30,
		EndMonoTimeTs:   30,
		EthProtocol:     3,
		Version:         2,
		SeenLongHdr:     0,
		SeenShortHdr:    1,
	})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 10, EndMonoTimeTs: 30, Packets: 3, EthProtocol: 3},
		QuicMetrics: &ebpf.BpfQuicMetrics{
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
	flow := BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{
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
	flow := BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{
		StartMonoTimeTs: 10,
		EndMonoTimeTs:   20,
		Packets:         3,
		EthProtocol:     2048,
	}}
	flow.AccumulateQuic(&ebpf.BpfQuicMetrics{
		StartMonoTimeTs: 25,
		EndMonoTimeTs:   25,
		EthProtocol:     2048,
		Version:         2,
		SeenLongHdr:     1,
		SeenShortHdr:    1,
	})
	flow.AccumulateQuic(&ebpf.BpfQuicMetrics{
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
	flow := BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{}}
	flow.AccumulateDNS(&ebpf.BpfDnsMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
		DNSMetrics:     &ebpf.BpfDnsMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
	}, flow)

	flow = BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{}}
	flow.AccumulateDrops(&ebpf.BpfPktDropMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
		PktDropMetrics: &ebpf.BpfPktDropMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
	}, flow)

	flow = BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{}}
	flow.AccumulateNetworkEvents(&ebpf.BpfNetworkEventsMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics:       &ebpf.BpfFlowMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
		NetworkEventsMetrics: &ebpf.BpfNetworkEventsMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
	}, flow)

	flow = BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{}}
	flow.AccumulateXlat(&ebpf.BpfXlatMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
		XlatMetrics:    &ebpf.BpfXlatMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
	}, flow)

	flow = BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{}}
	flow.AccumulateAdditional(&ebpf.BpfAdditionalMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics:    &ebpf.BpfFlowMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
		AdditionalMetrics: &ebpf.BpfAdditionalMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25},
	}, flow)

	flow = BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{}}
	flow.AccumulateQuic(&ebpf.BpfQuicMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25, EthProtocol: 3})
	assert.Equal(t, BpfFlowContent{
		BpfFlowMetrics: &ebpf.BpfFlowMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25, EthProtocol: 3},
		QuicMetrics:    &ebpf.BpfQuicMetrics{StartMonoTimeTs: 25, EndMonoTimeTs: 25, EthProtocol: 3},
	}, flow)
}
