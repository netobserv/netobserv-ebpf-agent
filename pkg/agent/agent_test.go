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
		TargetHost:         "127.0.0.1",
		TargetPort:         port,
		CacheMaxFlows:      1,
		ExcludeInterfaces:  []string{"ignored"},
		CacheActiveTimeout: 5 * time.Second,
		BuffersLength:      10,
	})
	require.NoError(t, err)

	// replace the interfaces informer by a fake
	ifacesCh := make(chan ifaces.Event, 10)
	flowsAgent.interfaces = &fakeInformer{events: ifacesCh}
	ifacesCh <- ifaces.Event{Type: ifaces.EventAdded, Interface: "fake"}
	ifacesCh <- ifaces.Event{Type: ifaces.EventAdded, Interface: "ignored"} // to be ignored

	// replacing the real eBPF tracer by a fake flow tracer
	agentInput := make(chan *flow.Record, 10)
	var ft *fakeFlowTracer
	flowsAgent.tracerFactory = func(name string, sampling uint32) flowTracer {
		if ft != nil {
			require.Fail(t, "flow tracer should have been instantiated only once")
		}
		ft = &fakeFlowTracer{tracedFlows: agentInput}
		return ft
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		require.NoError(t, flowsAgent.Run(ctx))
	}()

	firstFlowTime := time.Date(2022, 03, 21, 16, 33, 12, 123_456_789, time.UTC)
	fr1 := flow.Record{
		Interface:     "fake",
		TimeFlowStart: firstFlowTime,
		TimeFlowEnd:   firstFlowTime,
		Packets:       1,
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

	secondFlowTime := time.Date(2022, 03, 21, 16, 33, 17, 987_654_321, time.UTC)
	fr2 := fr1
	fr2.Bytes = 567
	fr2.TimeFlowStart = secondFlowTime
	fr2.TimeFlowEnd = secondFlowTime

	// WHEN new flows are traced
	agentInput <- &fr1
	agentInput <- &fr2
	agentInput <- &flow.Record{} // forces eviction

	// THEN the flows are aggregated and forwarded to the remote collector
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
	assert.False(t, ft.unregisterCalled)
	assert.False(t, ft.contextCanceled)

	// Trigger the removal of the interface and check that the tracer context is cancelled
	ifacesCh <- ifaces.Event{Type: ifaces.EventDeleted, Interface: "fake"}
	test.Eventually(t, timeout, func(t require.TestingT) {
		require.True(t, ft.contextCanceled)
	})
}

func TestFlowsAgent_DetachAllTracersOnExit(t *testing.T) {
	flowsAgent, err := FlowsAgent(&Config{
		TargetHost:         "127.0.0.1",
		TargetPort:         1234,
		CacheMaxFlows:      1,
		ExcludeInterfaces:  []string{"ignored"},
		CacheActiveTimeout: 5 * time.Second,
		BuffersLength:      10,
	})
	require.NoError(t, err)
	ifacesCh := make(chan ifaces.Event, 10)
	flowsAgent.interfaces = &fakeInformer{events: ifacesCh}
	ifacesCh <- ifaces.Event{Type: ifaces.EventAdded, Interface: "fake"}
	agentInput := make(chan *flow.Record, 10)
	var ft *fakeFlowTracer
	flowsAgent.tracerFactory = func(name string, sampling uint32) flowTracer {
		ft = &fakeFlowTracer{tracedFlows: agentInput}
		return ft
	}

	// GIVEN an agent with a registered flow tracer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		require.NoError(t, flowsAgent.Run(ctx))
	}()
	test.Eventually(t, timeout, func(t require.TestingT) {
		if ft == nil {
			t.FailNow()
		} else {
			assert.True(t, ft.registerCalled)
		}
	})

	// WHEN the agent is stopped
	cancel()

	// THEN its tracers are unregistered
	test.Eventually(t, timeout, func(t require.TestingT) {
		require.True(t, ft.unregisterCalled)
	})
}

func TestFlowsAgent_ValidateConfiguration(t *testing.T) {
	t.Fatal("IMPLEMENT THIS!")
}

type fakeFlowTracer struct {
	registerCalled   bool
	unregisterCalled bool
	contextCanceled  bool
	tracedFlows      <-chan *flow.Record
}

func (ft *fakeFlowTracer) Trace(ctx context.Context, forwardFlows chan<- *flow.Record) {
	for {
		select {
		case f := <-ft.tracedFlows:
			forwardFlows <- f
		case <-ctx.Done():
			ft.contextCanceled = true
		}
	}
}

func (ft *fakeFlowTracer) Register() error {
	ft.registerCalled = true
	return nil
}

func (ft *fakeFlowTracer) Unregister() error {
	ft.unregisterCalled = true
	return nil
}

type fakeInformer struct {
	events chan ifaces.Event
}

func (f *fakeInformer) Subscribe(_ context.Context) (<-chan ifaces.Event, error) {
	return f.events, nil
}
