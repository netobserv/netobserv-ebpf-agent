package flow

import (
	"context"
	"iter"
	"net"
	"slices"
	"testing"
	"time"

	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type endpointTestFetcher struct {
	*test.TracerFake
	requested []ebpf.BpfFlowId
	calls     int
}

func (f *endpointTestFetcher) ResolveEndpoints(ids iter.Seq[ebpf.BpfFlowId]) model.EndpointTable {
	f.calls++
	f.requested = slices.Collect(ids)
	return f.TracerFake.ResolveEndpoints(slices.Values(f.requested))
}

func TestExportBatchResolvesEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name, src, dst string
		ethProtocol    uint16
	}{
		{"ipv4", "192.0.2.1", "192.0.2.2", 0x0800},
		{"ipv6", "2001:db8::1", "2001:db8::2", 0x86dd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &endpointTestFetcher{TracerFake: test.NewTracerFake()}
			src := model.IPAddrFromNetIP(net.ParseIP(tc.src))
			dst := model.IPAddrFromNetIP(net.ParseIP(tc.dst))
			f.Endpoints = model.EndpointTable{1: src, 2: dst, 99: src}
			key := ebpf.BpfFlowId{SrcId: 1, DstId: 2, SrcPort: 1234, DstPort: 443, TransportProtocol: 6}
			value := ebpf.BpfFlowMetrics{EthProtocol: tc.ethProtocol, Packets: 1}
			m := metrics.NoOp()
			out := make(chan []*model.Record, 1)
			mt := NewMapTracer(f, time.Hour, time.Hour, m, nil, false)
			f.AppendLookupResults(map[ebpf.BpfFlowId]model.BpfFlowContent{key: model.NewBpfFlowContent(value)})
			mt.evictFlows(context.Background(), false, out)
			check := func(records []*model.Record) {
				t.Helper()
				require.Len(t, records, 1)
				assert.Equal(t, key, records[0].ID)
				assert.Equal(t, src, records[0].SrcAddr)
				assert.Equal(t, dst, records[0].DstAddr)
				assert.Equal(t, []ebpf.BpfFlowId{key}, f.requested)
			}
			check(<-out)

			acc := NewAccounter(10, time.Hour, time.Now, func() time.Duration { return 0 }, m, nil, false, f)
			acc.evict(map[ebpf.BpfFlowId]*ebpf.BpfFlowMetrics{key: &value}, out, "test")
			check(<-out)
			assert.Equal(t, 2, f.calls)

			mt.evictFlows(context.Background(), false, out)
			assert.Empty(t, <-out)
			acc.evict(nil, out, "test")
			assert.Empty(t, <-out)
			assert.Equal(t, 2, f.calls, "empty exports must not resolve endpoints")
		})
	}
}
