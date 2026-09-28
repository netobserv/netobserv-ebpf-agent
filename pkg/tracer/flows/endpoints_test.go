package flows

import (
	"slices"
	"testing"

	cilium "github.com/cilium/ebpf"
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveEndpoints(t *testing.T) {
	ipv4 := model.IPAddr{10: 0xff, 11: 0xff, 12: 192, 13: 0, 14: 2, 15: 1}
	ipv6 := model.IPAddr{0: 0x20, 1: 1, 2: 0xd, 3: 0xb8, 15: 1}
	dictionary := model.EndpointTable{1: ipv4, 2: ipv6, 99: ipv4}
	lookups := map[uint32]int{}
	lookup := func(key, out any) error {
		id := *key.(*uint32)
		lookups[id]++
		addr, ok := dictionary[id]
		if !ok {
			return cilium.ErrKeyNotExist
		}
		out.(*ebpf.BpfEndpointAddr).Ip = addr
		return nil
	}
	ids := []ebpf.BpfFlowId{
		{SrcId: 1, DstId: 2},
		{SrcId: 2, DstId: 1},
		{SrcId: 1, DstId: 1},
		{SrcId: 0, DstId: 3},
		{SrcId: 3, DstId: 1},
	}
	table := resolveEndpoints(slices.Values(ids), lookup)
	assert.Equal(t, model.EndpointTable{1: ipv4, 2: ipv6}, table)
	assert.Equal(t, map[uint32]int{1: 1, 2: 1, 3: 1}, lookups,
		"resolve shared and missing IDs once; never read ID zero or unrelated entries")
	_, _, ok := table.Addrs(ids[4])
	assert.False(t, ok, "missing endpoints must remain unresolved")

	// A miss in one batch must not poison the next batch.
	dictionary[3] = ipv6
	table = resolveEndpoints(slices.Values(ids[4:]), lookup)
	src, dst, ok := table.Addrs(ids[4])
	require.True(t, ok)
	assert.Equal(t, ipv6, src)
	assert.Equal(t, ipv4, dst)
}

func TestResolveEndpointsEmptyBatch(t *testing.T) {
	table := resolveEndpoints(slices.Values([]ebpf.BpfFlowId{}), func(_, _ any) error {
		t.Fatal("empty batch must not access the endpoint map")
		return nil
	})
	assert.Empty(t, table)
}
