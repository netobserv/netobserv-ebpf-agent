package model

import (
	"math"
	"sync"
	"unsafe"

	ebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
)

// FlowBatch is a batch of flow records held by the processing pipeline. Its
// estimated size is reserved against the agent's in-flight batch budget until
// the exporter has finished processing it.
type FlowBatch struct {
	Records        []*Record
	EstimatedBytes uint64
	release        func()
	releaseOnce    sync.Once
}

// NewFlowBatch creates a batch whose budget reservation is released by Release.
func NewFlowBatch(records []*Record, estimatedBytes uint64, release func()) *FlowBatch {
	return &FlowBatch{Records: records, EstimatedBytes: estimatedBytes, release: release}
}

// Release returns this batch's reservation. Exporters must call it after they
// have finished processing the records.
func (b *FlowBatch) Release() {
	if b != nil && b.release != nil {
		b.releaseOnce.Do(b.release)
	}
}

// EstimateFlowBatchBytes estimates the retained Go memory for a batch. It
// includes record and metrics structures, slice storage, and variable-sized
// strings and event metadata. It includes a fixed margin for exporter-side
// conversions and allocator overhead; this is a budget estimate, not an exact
// heap profile.
func EstimateFlowBatchBytes(records []*Record) uint64 {
	bytes := uint64(unsafe.Sizeof(FlowBatch{})) + uint64(cap(records))*uint64(unsafe.Sizeof((*Record)(nil)))
	for _, record := range records {
		if record == nil {
			continue
		}
		bytes = addEstimate(bytes,
			uint64(unsafe.Sizeof(*record)),
			uint64(unsafe.Sizeof(BpfFlowContent{})),
			uint64(unsafe.Sizeof(ebpf.FlowsBpfFlowMetrics{})),
			96, // pointer allocations and allocator size-class overhead
		)
		bytes = addEstimate(bytes, uint64(cap(record.Interfaces))*uint64(unsafe.Sizeof(IntfDirUdn{})))
		for _, iface := range record.Interfaces {
			bytes = addEstimate(bytes, uint64(len(iface.Interface)), uint64(len(iface.Udn)), 32)
		}
		if record.AgentIP != nil {
			bytes = addEstimate(bytes, uint64(cap(record.AgentIP)), 16)
		}
		if record.Metrics.DNSMetrics != nil {
			bytes = addEstimate(bytes, uint64(unsafe.Sizeof(*record.Metrics.DNSMetrics)), 16)
		}
		if record.Metrics.PktDropMetrics != nil {
			bytes = addEstimate(bytes, uint64(unsafe.Sizeof(*record.Metrics.PktDropMetrics)), 16)
		}
		if record.Metrics.NetworkEventsMetrics != nil {
			bytes = addEstimate(bytes, uint64(unsafe.Sizeof(*record.Metrics.NetworkEventsMetrics)), 16)
		}
		if record.Metrics.XlatMetrics != nil {
			bytes = addEstimate(bytes, uint64(unsafe.Sizeof(*record.Metrics.XlatMetrics)), 16)
		}
		if record.Metrics.AdditionalMetrics != nil {
			bytes = addEstimate(bytes, uint64(unsafe.Sizeof(*record.Metrics.AdditionalMetrics)), 16)
		}
		if record.Metrics.QuicMetrics != nil {
			bytes = addEstimate(bytes, uint64(unsafe.Sizeof(*record.Metrics.QuicMetrics)), 16)
		}
		for _, metadata := range record.NetworkMonitorEventsMD {
			bytes = addEstimate(bytes, 128) // map header and buckets
			for key, value := range metadata {
				bytes = addEstimate(bytes, uint64(len(key)), uint64(len(value)), 32)
			}
		}
	}
	return addEstimate(bytes, bytes)
}

func addEstimate(total uint64, values ...uint64) uint64 {
	for _, value := range values {
		if math.MaxUint64-total < value {
			return math.MaxUint64
		}
		total += value
	}
	return total
}
