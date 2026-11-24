package model

import (
	"fmt"
	"testing"
)

var estimateFlowBatchBytesSink uint64

// BenchmarkEstimateFlowBatchBytes measures the per-batch admission-check cost
// for cache-sized batches. Fixtures are prepared before timing so the result
// reflects sizing work rather than record construction.
func BenchmarkEstimateFlowBatchBytes(b *testing.B) {
	for _, flowCount := range []int{1_000, 10_000, 100_000} {
		for _, interfacesPerFlow := range []int{1, 3} {
			name := fmt.Sprintf("%d-flows/%d-interfaces", flowCount, interfacesPerFlow)
			b.Run(name, func(b *testing.B) {
				records := make([]*Record, flowCount)
				for i := range records {
					interfaces := make([]IntfDirUdn, interfacesPerFlow)
					for j := range interfaces {
						interfaces[j] = IntfDirUdn{
							Interface: fmt.Sprintf("veth-%05d-%d", i, j),
							Direction: j % 2,
							Udn:       "tenant-default",
						}
					}
					records[i] = &Record{
						Metrics:    benchFlowContent(i),
						Interfaces: interfaces,
					}
				}

				estimatedBytes := EstimateFlowBatchBytes(records)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					estimateFlowBatchBytesSink = EstimateFlowBatchBytes(records)
				}
				b.ReportMetric(float64(estimatedBytes)/float64(flowCount), "est-B/flow")
			})
		}
	}
}
