package exporter

import (
	"net"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	test2 "github.com/netobserv/netobserv-ebpf-agent/pkg/test"

	"github.com/mariomac/guara/pkg/test"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	grpc "github.com/netobserv/netobserv-ebpf-agent/pkg/grpc/flow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const timeout = 2 * time.Second

func TestIPv4GRPCProto_ExportFlows_AgentIP(t *testing.T) {
	// start remote ingestor
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	serverOut := make(chan *pbflow.Records)
	coll, err := grpc.StartCollector(port, serverOut)
	require.NoError(t, err)
	defer coll.Close()

	// Start GRPCProto exporter stage
	exporter, err := StartGRPCProto("127.0.0.1", port, 1000, metrics.NewMetrics(&metrics.Settings{}), nil)
	require.NoError(t, err)

	// Send some flows to the input of the exporter stage
	flows := make(chan []*model.Record, 10)
	flows <- []*model.Record{
		{AgentIP: net.ParseIP("10.9.8.7")},
	}
	flows <- []*model.Record{
		{RawRecord: model.RawRecord{Id: ebpf.BpfFlowId{EthProtocol: model.IPv6Type}},
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
	coll, err := grpc.StartCollector(port, serverOut)
	require.NoError(t, err)
	defer coll.Close()

	// Start GRPCProto exporter stage
	exporter, err := StartGRPCProto("::1", port, 1000, metrics.NewMetrics(&metrics.Settings{}), nil)
	require.NoError(t, err)

	// Send some flows to the input of the exporter stage
	flows := make(chan []*model.Record, 10)
	flows <- []*model.Record{
		{AgentIP: net.ParseIP("10.11.12.13")},
	}
	flows <- []*model.Record{
		{RawRecord: model.RawRecord{Id: ebpf.BpfFlowId{EthProtocol: model.IPv6Type}},
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
	coll, err := grpc.StartCollector(port, serverOut)
	require.NoError(t, err)
	defer coll.Close()

	const msgMaxLen = 10000
	// Start GRPCProto exporter stage
	exporter, err := StartGRPCProto("127.0.0.1", port, msgMaxLen, metrics.NewMetrics(&metrics.Settings{}), nil)
	require.NoError(t, err)

	// Send a message much longer than the limit length
	flows := make(chan []*model.Record, 10)
	var input []*model.Record
	for i := 0; i < 25000; i++ {
		input = append(input, &model.Record{RawRecord: model.RawRecord{Id: ebpf.BpfFlowId{
			EthProtocol: model.IPv6Type,
		}}, AgentIP: net.ParseIP("1111::1111"), Interface: "12345678"})
	}
	flows <- input
	go exporter.ExportFlows(flows)

	// expect that the submitted message is split in chunks no longer than msgMaxLen
	rs := test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, msgMaxLen)
	rs = test2.ReceiveTimeout(t, serverOut, timeout)
	assert.Len(t, rs.Entries, msgMaxLen)
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
