package exporter

import (
	"context"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	grpc2 "google.golang.org/grpc"
)

func TestGRPCProto_NoBatch(t *testing.T) {
	capturer := collectorCapturer{}
	gp := &GRPCProto{clientConn: &capturer}
	flows := make(chan []*flow.Record, 10)
	// sending 8 flows
	flows <- []*flow.Record{{}, {}, {}, {}, {}, {}, {}, {}}
	close(flows)
	gp.ExportFlows(flows)

	// Expecting that all the flows are submitted in a batch
	require.Len(t, capturer.submitted, 1)
	assert.Len(t, capturer.submitted[0].Entries, 8)

	// Expecting that connection is closed
	assert.True(t, capturer.closed)
}

func TestGRPCProto_Batching(t *testing.T) {
	capturer := collectorCapturer{}
	gp := &GRPCProto{
		maxMessageEntries: 3,
		clientConn:        &capturer,
	}
	flows := make(chan []*flow.Record, 10)
	// sending 8 flows
	flows <- []*flow.Record{{}, {}, {}, {}, {}, {}, {}, {}}
	close(flows)
	gp.ExportFlows(flows)

	// Expecting that the message has been divided in entries of max 3 flows
	require.Len(t, capturer.submitted, 3)
	assert.Len(t, capturer.submitted[0].Entries, 3)
	assert.Len(t, capturer.submitted[1].Entries, 3)
	assert.Len(t, capturer.submitted[2].Entries, 2)

	// Expecting that connection is closed
	assert.True(t, capturer.closed)
}

type collectorCapturer struct {
	submitted []*pbflow.Records
	closed    bool
}

func (c *collectorCapturer) Close() error {
	c.closed = true
	return nil
}

func (c *collectorCapturer) Client() pbflow.CollectorClient {
	return c
}

func (c *collectorCapturer) Send(_ context.Context, in *pbflow.Records, _ ...grpc2.CallOption) (*pbflow.CollectorReply, error) {
	c.submitted = append(c.submitted, in)
	return nil, nil
}
