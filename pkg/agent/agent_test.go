package agent

import (
	"context"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/grpc"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ifaces"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const timeout = 5 * time.Second

func TestFlowsAgent(t *testing.T) {
	// preparing a test flow collector
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	collectedRecords := make(chan *pbflow.Records, 10)
	collector, err := grpc.StartCollector(port, collectedRecords)
	require.NoError(t, err)
	defer collector.Close()

	// GIVEN a flows agent
	flowsAgent, err := FlowsAgent(&Config{
		Export:             "grpc",
		TargetHost:         "127.0.0.1",
		TargetPort:         port,
		ExcludeInterfaces:  []string{"ignored"},
		CacheActiveTimeout: 5 * time.Second,
		BuffersLength:      10,
	})
	require.NoError(t, err)

	// replace the interfaces informer by a fake
	ifacesCh := make(chan ifaces.Event, 10)
	flowsAgent.interfaces = &fakeInformer{events: ifacesCh}
	ifacesCh <- ifaces.Event{Type: ifaces.EventAdded, Interface: ifaces.Interface{"fake", 1}}
	ifacesCh <- ifaces.Event{Type: ifaces.EventAdded, Interface: ifaces.Interface{"ignored", 2}} // to be ignored

	// replacing the real eBPF tracer by a fake flow tracer
	agentInput := make(chan *flow.Record, 10)
	var ft *fakeFlowTracer
	flowsAgent.tracer = &fakeFlowTracer{tracedFlows: agentInput}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		require.NoError(t, flowsAgent.Run(ctx))
	}()

	firstFlowTime := time.Date(2022, 03, 21, 16, 33, 12, 123_456_789, time.UTC)
	secondFlowTime := time.Date(2022, 03, 21, 16, 33, 17, 987_654_321, time.UTC)
	fr1 := flow.Record{
		Interface:     "fake",
		TimeFlowStart: firstFlowTime,
		TimeFlowEnd:   secondFlowTime,
	}
	fr1.EthProtocol = 2048
	fr1.Direction = 1 // egress
	fr1.DataLink.SrcMac = flow.MacAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	fr1.DataLink.DstMac = flow.MacAddr{0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC}
	fr1.Network.SrcAddr = flow.IPAddr{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
		0x11, 0x22, 0x33, 0x44}
	fr1.Network.DstAddr = flow.IPAddr{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
		0xaa, 0xbb, 0xcc, 0xdd}
	fr1.Transport.Protocol = 123
	fr1.Transport.SrcPort = 456
	fr1.Transport.DstPort = 789
	fr1.Bytes = 1_234_000
	fr1.Packets = 1

	// WHEN new flow us traced
	agentInput <- &fr1

	// THEN the flows is forwarded to the remote collector
	var rs *pbflow.Records
	select {
	case rs = <-collectedRecords:
	case <-time.After(timeout):
		require.Fail(t, "timeout waiting for flows")
	}
	assert.Len(t, rs.Entries, 1)
	r := rs.Entries[0]
	assert.Equal(t, "fake", r.Interface)
	assert.Equal(t, firstFlowTime, r.TimeFlowStart.AsTime())
	assert.Equal(t, secondFlowTime, r.TimeFlowEnd.AsTime())
	assert.EqualValues(t, 2, r.Packets)
	assert.EqualValues(t, 2048, r.EthProtocol)
	assert.EqualValues(t, 1, r.Direction)
	assert.EqualValues(t, 0x112233445566, r.DataLink.SrcMac)
	assert.EqualValues(t, 0x778899aabbcc, r.DataLink.DstMac)
	assert.EqualValues(t, 0x11223344, r.Network.SrcAddr.GetIpv4())
	assert.EqualValues(t, 0xaabbccdd, r.Network.DstAddr.GetIpv4())
	assert.EqualValues(t, 123, r.Transport.Protocol)
	assert.EqualValues(t, 456, r.Transport.SrcPort)
	assert.EqualValues(t, 789, r.Transport.DstPort)
	assert.EqualValues(t, 1_234_567, r.Bytes)

	// Check that during the initialization, the flow tracer was registered
	assert.True(t, ft.registerCalled)
	assert.False(t, ft.contextCanceled)

	// Trigger the removal of the interface and check that the tracer context is cancelled
	ifacesCh <- ifaces.Event{Type: ifaces.EventDeleted, Interface: ifaces.Interface{"fake", 1}}
	test.Eventually(t, timeout, func(t require.TestingT) {
		require.True(t, ft.contextCanceled)
	})
}

func TestFlowsAgent_InvalidConfigs(t *testing.T) {
	for _, tc := range []struct {
		d string
		c Config
	}{{
		d: "invalid export type",
		c: Config{Export: "foo"},
	}, {
		d: "GRPC: missing host",
		c: Config{Export: "grpc", TargetPort: 3333},
	}, {
		d: "GRPC: missing port",
		c: Config{Export: "grpc", TargetHost: "flp"},
	}, {
		d: "Kafka: missing brokers",
		c: Config{Export: "kafka"},
	}} {
		t.Run(tc.d, func(t *testing.T) {
			_, err := FlowsAgent(&tc.c)
			assert.Error(t, err)
		})
	}
}

type fakeFlowTracer struct {
	registerCalled  bool
	contextCanceled bool
	tracedFlows     <-chan *flow.Record
}

func (ft *fakeFlowTracer) Trace(ctx context.Context, forwardFlows chan<- []*flow.Record) {
	for {
		select {
		case f := <-ft.tracedFlows:
			forwardFlows <- []*flow.Record{f}
		case <-ctx.Done():
			ft.contextCanceled = true
		}
	}
}

func (ft *fakeFlowTracer) Register(_ ifaces.Interface) error {
	ft.registerCalled = true
	return nil
}

type fakeInformer struct {
	events chan ifaces.Event
}

func (f *fakeInformer) Subscribe(_ context.Context) (<-chan ifaces.Event, error) {
	return f.events, nil
}
