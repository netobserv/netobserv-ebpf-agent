package flows

import (
	"iter"

	cilium "github.com/cilium/ebpf"
	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

// ResolveEndpoints reads each endpoint referenced by this batch once. No state is
// retained between batches, so work and userspace memory do not grow with the
// lifetime of the kernel dictionary. The dictionary itself is append-only.
func (m *Fetcher) ResolveEndpoints(ids iter.Seq[ebpf.BpfFlowId]) model.EndpointTable {
	if m.objects == nil || m.objects.EndpointIps == nil {
		return nil
	}
	m.observeEndpointMaps()
	return resolveEndpoints(ids, m.objects.EndpointIps.Lookup)
}

// observeEndpointMaps exports the bounded endpoint dictionaries' occupancy and
// kernel allocation. The maps are append-only for the lifetime of the agent,
// so the ID counter is also the endpoint high-water mark.
func (m *Fetcher) observeEndpointMaps() {
	if m.metrics == nil || m.objects == nil {
		return
	}
	m.endpointMapInfoOnce.Do(func() {
		for name, bpfMap := range map[string]*cilium.Map{
			ebpf.BpfMapEndpointIds: m.objects.EndpointIds,
			ebpf.BpfMapEndpointIps: m.objects.EndpointIps,
		} {
			if bpfMap == nil {
				continue
			}
			info, err := bpfMap.Info()
			if err != nil {
				log.WithError(err).WithField("map", name).Debug("couldn't inspect endpoint map")
				continue
			}
			m.metrics.EndpointMapMaxEntries.WithLabelValues(name).Set(float64(info.MaxEntries))
			if bytes, ok := info.Memlock(); ok {
				m.metrics.EndpointMapMemlockBytes.WithLabelValues(name).Set(float64(bytes))
			}
		}
	})

	var zero, next uint32
	if m.objects.EndpointIdCounter == nil {
		return
	}
	if err := m.objects.EndpointIdCounter.Lookup(&zero, &next); err != nil {
		log.WithError(err).Debug("couldn't read endpoint ID counter")
		return
	}
	entries := float64(0)
	if next > 0 {
		entries = float64(next - 1)
	}
	for _, name := range []string{ebpf.BpfMapEndpointIds, ebpf.BpfMapEndpointIps} {
		m.metrics.EndpointMapEntries.WithLabelValues(name).Set(entries)
	}
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
