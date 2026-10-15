package flows

import (
	"iter"

	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

// ResolveEndpoints reads only endpoint IDs referenced by the current export batch.
// It never snapshots the full reverse map or retains addresses between batches.
func (m *Fetcher) ResolveEndpoints(ids iter.Seq[ebpf.BpfFlowId]) model.EndpointTable {
	if m.objects == nil || m.objects.EndpointIps == nil {
		return nil
	}
	return resolveEndpoints(ids, m.objects.EndpointIps.Lookup)
}

func resolveEndpoints(ids iter.Seq[ebpf.BpfFlowId], lookup func(key, valueOut any) error) model.EndpointTable {
	table := make(model.EndpointTable)
	for id := range ids {
		if id.SrcId != 0 {
			table[id.SrcId] = model.IPAddr{}
		}
		if id.DstId != 0 {
			table[id.DstId] = model.IPAddr{}
		}
	}
	if len(table) == 0 {
		return nil
	}
	// Reuse syscall input/output storage instead of allocating it for every ID.
	var id uint32
	var addr ebpf.BpfEndpointAddr
	for id = range table {
		if err := lookup(&id, &addr); err != nil {
			// Leave failed lookups absent: the exporter must report unresolved
			// addresses instead of treating a zero-filled address as resolved.
			log.WithError(err).WithField("endpointID", id).Warn("couldn't resolve endpoint")
			delete(table, id)
			continue
		}
		table[id] = model.IPAddr(addr.Ip)
	}
	return table
}
