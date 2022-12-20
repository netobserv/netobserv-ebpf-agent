package exporter

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/grpc"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const timeout = 2 * time.Second

func TestGRPCProto_ExportFlows_AgentIP(t *testing.T) {
	// start remote ingestor
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	serverOut := make(chan *pbflow.Records)
	_, err = grpc.StartCollector(port, serverOut)
	require.NoError(t, err)

	// Start GRPCProto exporter stage
	exporter, err := StartGRPCProto(fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)

	// Send some flows to the input of the exporter stage
	flows := make(chan []*flow.Record, 10)
	flows <- []*flow.Record{
		{AgentIP: net.ParseIP("10.9.8.7")},
	}
	flows <- []*flow.Record{
		{RawRecord: flow.RawRecord{RecordKey: flow.RecordKey{EthProtocol: flow.IPv6Type}},
			AgentIP: net.ParseIP("8888::1111")},
	}
	close(flows)
	go exporter.ExportFlows(flows)

	var rs *pbflow.Records
	select {
	case rs = <-serverOut:
	case <-time.After(timeout):
		require.Fail(t, "timeout waiting for flows")
	}
	assert.Len(t, rs.Entries, 1)
	r := rs.Entries[0]
	assert.EqualValues(t, 0x0a090807, r.GetAgentIp().GetIpv4())
	select {
	case rs = <-serverOut:
	case <-time.After(timeout):
		require.Fail(t, "timeout waiting for flows")
	}
	assert.Len(t, rs.Entries, 1)
	r = rs.Entries[0]
	assert.EqualValues(t, net.ParseIP("8888::1111"), r.GetAgentIp().GetIpv6())

	select {
	case rs = <-serverOut:
		assert.Failf(t, "shouldn't have received any flow", "Got: %#v", rs)
	default:
		//ok!
	}
}
