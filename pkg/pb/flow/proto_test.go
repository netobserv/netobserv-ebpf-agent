package pbflow

import (
	"runtime"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestForEachFlowBatchPreservesRecordsAndBoundsBatchSize(t *testing.T) {
	input := make([]*model.Record, 23)
	for i := range input {
		input[i] = benchRecord(i + 1)
		input[i].Metrics.Bytes = uint64(i + 1)
	}

	var got []*Record
	var batchSizes []int
	ForEachFlowBatch(input, 10, func(batch *Records) {
		batchSizes = append(batchSizes, len(batch.Entries))
		got = append(got, batch.Entries...)
	})

	require.Equal(t, []int{10, 10, 3}, batchSizes)
	require.Len(t, got, len(input))
	for i, record := range input {
		require.True(t, proto.Equal(FlowToPB(record), got[i]), "record %d changed", i)
	}
}

func TestForEachFlowBatchLargeEvictionPeakHeap(t *testing.T) {
	const (
		flowCount = 120_000
		batchSize = 10_000
	)
	input := make([]*model.Record, flowCount)
	for i := range input {
		input[i] = benchRecord(i)
	}

	runtime.GC()
	var baseline, current runtime.MemStats
	runtime.ReadMemStats(&baseline)
	peakHeapGrowth := uint64(0)
	peakBatchRecords := 0
	converted := 0
	ForEachFlowBatch(input, batchSize, func(batch *Records) {
		runtime.ReadMemStats(&current)
		if current.HeapAlloc > baseline.HeapAlloc {
			peakHeapGrowth = max(peakHeapGrowth, current.HeapAlloc-baseline.HeapAlloc)
		}
		peakBatchRecords = max(peakBatchRecords, len(batch.Entries))
		converted += len(batch.Entries)
	})

	require.Equal(t, flowCount, converted)
	require.Equal(t, batchSize, peakBatchRecords)
	t.Logf("peak heap growth at a completed chunk: %d bytes; peak protobuf chunk: %d records", peakHeapGrowth, peakBatchRecords)
}
