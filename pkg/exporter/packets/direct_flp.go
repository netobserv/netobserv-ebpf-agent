package packets

import exporterflows "github.com/netobserv/netobserv-ebpf-agent/pkg/exporter/flows"

// DirectFLP embeds an in-process flowlogs-pipeline for packet export.
type DirectFLP = exporterflows.DirectFLP

// StartDirectFLP starts an in-process flowlogs-pipeline configured for packet export.
func StartDirectFLP(jsonConfig string, bufLen int) (*DirectFLP, error) {
	return exporterflows.StartDirectFLP(jsonConfig, bufLen)
}
