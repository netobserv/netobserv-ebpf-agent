package exporter

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	grpcflow "github.com/netobserv/netobserv-ebpf-agent/pkg/grpc/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	test2 "github.com/netobserv/netobserv-ebpf-agent/pkg/test"

	"github.com/mariomac/guara/pkg/test"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/peer"
)

const timeout = 2 * time.Second

func TestIPv4GRPCProto_ExportFlows_AgentIP(t *testing.T) {
	// start remote ingestor
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	serverOut := make(chan *pbflow.Records)
	coll, err := grpcflow.StartCollector(port, serverOut)
	require.NoError(t, err)
	defer coll.Close()

	// Start GRPCProto exporter stage
	cfg := config.Agent{
		TargetHost:          "127.0.0.1",
		TargetPort:          port,
		GRPCMessageMaxFlows: 1000,
	}
	exporter, err := StartGRPCProto(&cfg, metrics.NoOp())
	require.NoError(t, err)

	// Send some flows to the input of the exporter stage
	flows := make(chan []*model.Record, 10)
	flows <- []*model.Record{
		{AgentIP: net.ParseIP("10.9.8.7"), Metrics: model.BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{}}},
	}
	flows <- []*model.Record{
		{Metrics: model.BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{EthProtocol: model.IPv6Type}},
			AgentIP: net.ParseIP("8888::1111")},
	}
	go exporter.ExportFlows(flows)

	rs := test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, 1)
	r := rs.Entries[0]
	assert.EqualValues(t, 0x0a090807, r.GetAgentIp().GetIpv4())

	rs = test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, 1)
	r = rs.Entries[0]
	assert.EqualValues(t, net.ParseIP("8888::1111"), r.GetAgentIp().GetIpv6())

	select {
	case rs = <-serverOut:
		assert.Failf(t, "shouldn't have received any flow", "Got: %#v", rs)
	default:
		// ok!
	}
}

func TestIPv6GRPCProto_ExportFlows_AgentIP(t *testing.T) {
	// start remote ingestor
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	serverOut := make(chan *pbflow.Records)
	coll, err := grpcflow.StartCollector(port, serverOut)
	require.NoError(t, err)
	defer coll.Close()

	// Start GRPCProto exporter stage
	cfg := config.Agent{
		TargetHost:          "::1",
		TargetPort:          port,
		GRPCMessageMaxFlows: 1000,
	}
	exporter, err := StartGRPCProto(&cfg, metrics.NoOp())
	require.NoError(t, err)

	// Send some flows to the input of the exporter stage
	flows := make(chan []*model.Record, 10)
	flows <- []*model.Record{
		{AgentIP: net.ParseIP("10.11.12.13"), Metrics: model.BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{}}},
	}
	flows <- []*model.Record{
		{Metrics: model.BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{EthProtocol: model.IPv6Type}},
			AgentIP: net.ParseIP("9999::2222")},
	}
	go exporter.ExportFlows(flows)

	rs := test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, 1)
	r := rs.Entries[0]
	assert.EqualValues(t, 0x0a0b0c0d, r.GetAgentIp().GetIpv4())

	rs = test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, 1)
	r = rs.Entries[0]
	assert.EqualValues(t, net.ParseIP("9999::2222"), r.GetAgentIp().GetIpv6())

	select {
	case rs = <-serverOut:
		assert.Failf(t, "shouldn't have received any flow", "Got: %#v", rs)
	default:
		// ok!
	}
}

func TestGRPCProto_SplitLargeMessages(t *testing.T) {
	// start remote ingestor
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	serverOut := make(chan *pbflow.Records)
	coll, err := grpcflow.StartCollector(port, serverOut)
	require.NoError(t, err)
	defer coll.Close()

	// Start GRPCProto exporter stage
	cfg := config.Agent{
		TargetHost:          "127.0.0.1",
		TargetPort:          port,
		GRPCMessageMaxFlows: 10_000,
	}
	exporter, err := StartGRPCProto(&cfg, metrics.NoOp())
	require.NoError(t, err)

	// Send a message much longer than the limit length
	flows := make(chan []*model.Record, 10)
	var input []*model.Record
	for i := 0; i < 25000; i++ {
		input = append(input, &model.Record{Metrics: model.BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{
			EthProtocol: model.IPv6Type,
		}}, AgentIP: net.ParseIP("1111::1111"), Interfaces: []model.IntfDirUdn{model.NewIntfDirUdn("12345678", 0, nil)}})
	}
	flows <- input
	go exporter.ExportFlows(flows)

	// expect that the submitted message is split in chunks no longer than msgMaxLen
	rs := test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, cfg.GRPCMessageMaxFlows)
	rs = test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, cfg.GRPCMessageMaxFlows)
	rs = test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, 5000)

	// after all the operation, no more flows are sent
	select {
	case rs = <-serverOut:
		assert.Failf(t, "shouldn't have received any flow", "Got: %#v", rs)
	default:
		// ok!
	}
}

type collectorAPI struct {
	pbflow.UnimplementedCollectorServer
	recordForwarder   chan<- *pbflow.Records
	lastClient        string
	clientOccurrences []int
}

func (c *collectorAPI) Send(ctx context.Context, records *pbflow.Records) (*pbflow.CollectorReply, error) {
	if p, ok := peer.FromContext(ctx); ok {
		addr := p.Addr.String()
		if len(c.clientOccurrences) == 0 || addr != c.lastClient {
			c.clientOccurrences = append(c.clientOccurrences, 1)
			c.lastClient = addr
		} else {
			c.clientOccurrences[len(c.clientOccurrences)-1]++
		}
	}
	c.recordForwarder <- records
	return &pbflow.CollectorReply{}, nil
}

func TestConnectionReset(t *testing.T) {
	// start remote ingestor
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	serverOut := make(chan *pbflow.Records)

	api := collectorAPI{
		recordForwarder:   serverOut,
		clientOccurrences: []int{},
	}
	coll, err := grpcflow.StartCollectorWithAPI(port, &api)
	require.NoError(t, err)
	defer coll.Close()

	// Start GRPCProto exporter stage
	cfg := config.Agent{
		TargetHost:          "127.0.0.1",
		TargetPort:          port,
		GRPCMessageMaxFlows: 1000,
		GRPCReconnectTimer:  500 * time.Millisecond,
	}
	exporter, err := StartGRPCProto(&cfg, metrics.NoOp())
	require.NoError(t, err)

	// Send some flows to the input of the exporter stage
	nFlows := 5
	flows := make(chan []*model.Record, nFlows+1)
	go exporter.ExportFlows(flows)
	go func() {
		for i := range nFlows {
			flows <- []*model.Record{
				{AgentIP: net.ParseIP(fmt.Sprintf("10.9.8.%d", i)), Metrics: model.BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{}}},
			}
			time.Sleep(300 * time.Millisecond)
		}
	}()

	for i := 0; i < nFlows; i++ {
		rs := test2.ReceiveTimeout(t, serverOut, timeout)
		assert.Len(t, rs.Entries, 1)
		r := rs.Entries[0]
		assert.EqualValues(t, 0x0a090800+i, r.GetAgentIp().GetIpv4())
	}

	// Expect flows sent at +0ms, +300ms | +600ms, +900ms | +1200ms ("|" means reconnect event / new client detected)
	// If it ends up too flaky, we can increase the durations, e.g. over 5s, or relax the assertion
	assert.Equal(t, []int{2, 2, 1}, api.clientOccurrences)

	select {
	case rs := <-serverOut:
		assert.Failf(t, "shouldn't have received any flow", "Got: %#v", rs)
	default:
		// ok!
	}
}

func TestRandomizeMaxMessages(t *testing.T) {
	for i := 0; i < 1000; i++ {
		v := randomizeTimer(&config.Agent{
			GRPCReconnectTimer:              5 * time.Minute,
			GRPCReconnectTimerRandomization: 30 * time.Second,
		})
		assert.GreaterOrEqual(t, v, 270*time.Second /*4m30s*/)
		assert.LessOrEqual(t, v, 330*time.Second /*5m30s*/)
	}
}
