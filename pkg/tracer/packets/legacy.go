package packets

import (
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
)

// Legacy implementations kept for old kernels.

func (p *Fetcher) legacyLookupAndDeleteMap(met *metrics.Metrics) map[int][]*byte {
	packetMap := p.objects.PacketRecord
	iterator := packetMap.Iterate()
	packets := make(map[int][]*byte, p.cacheMaxSize)

	var id int
	var packet []*byte
	for iterator.Next(&id, &packet) {
		if err := packetMap.Delete(id); err != nil {
			plog.WithError(err).WithField("packetID ", id).Warnf("couldn't delete  entry")
			met.Errors.WithErrorName("pkt-fetcher-legacy", "CannotDeleteEntry", metrics.HighSeverity).Inc()
		}
		packets[id] = append(packets[id], packet...)
	}
	return packets
}
