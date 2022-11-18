package agent

import "github.com/netobserv/netobserv-ebpf-agent/pkg/flow"

type ExporterPlugin func(*Config) (Exporter, error)

type Exporter interface {
	ExportFlows(input <-chan []*flow.Record)
}
