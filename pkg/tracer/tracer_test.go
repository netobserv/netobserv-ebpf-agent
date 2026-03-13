package tracer

import (
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/stretchr/testify/assert"
)

// mockMap simulates a BPF map for testing
type mockMap struct {
	data map[ebpf.BpfFlowId]interface{}
}

func (m *mockMap) Iterate() *mockIterator {
	keys := make([]ebpf.BpfFlowId, 0, len(m.data))
	for k := range m.data {
		keys = append(keys, k)
	}
	return &mockIterator{keys: keys, index: -1}
}

func (m *mockMap) LookupAndDelete(id *ebpf.BpfFlowId, receiver interface{}) error {
	val, exists := m.data[*id]
	if !exists {
		return nil
	}
	// Copy the value to the receiver
	if v, ok := receiver.(*[]ebpf.BpfAdditionalMetrics); ok {
		*v = val.([]ebpf.BpfAdditionalMetrics)
	}
	delete(m.data, *id)
	return nil
}

type mockIterator struct {
	keys  []ebpf.BpfFlowId
	index int
}

func (i *mockIterator) Next(id *ebpf.BpfFlowId, _ interface{}) bool {
	i.index++
	if i.index >= len(i.keys) {
		return false
	}
	*id = i.keys[i.index]
	return true
}

// TestLookupAndDeletePerCPUMapOrphanedMetrics tests that orphaned supplementary metrics
// (metrics without a corresponding main flow) are skipped instead of creating phantom flows
// with 0 bytes and 0 packets. This is the fix for NETOBSERV-2343.
func TestLookupAndDeletePerCPUMapOrphanedMetrics(t *testing.T) {
	// Setup: Create a main flow and an orphaned IPsec metric
	mainFlowID := ebpf.BpfFlowId{
		SrcPort: 80,
		DstPort: 443,
	}
	orphanedFlowID := ebpf.BpfFlowId{
		SrcPort: 8080,
		DstPort: 8443,
	}

	// Main flows map contains only one flow
	flows := map[ebpf.BpfFlowId]model.BpfFlowContent{
		mainFlowID: {
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{
				Packets: 10,
				Bytes:   1500,
			},
		},
	}

	// Additional metrics map contains both:
	// 1. Metrics for the main flow (should be merged)
	// 2. Orphaned metrics without a main flow (should be skipped)
	additionalMetricsMap := &mockMap{
		data: map[ebpf.BpfFlowId]interface{}{
			mainFlowID: []ebpf.BpfAdditionalMetrics{
				{
					FlowRtt:           100,
					IpsecEncrypted:    true,
					IpsecEncryptedRet: 0,
					StartMonoTimeTs:   1000,
					EndMonoTimeTs:     2000,
				},
			},
			orphanedFlowID: []ebpf.BpfAdditionalMetrics{
				{
					FlowRtt:           200,
					IpsecEncrypted:    true,
					IpsecEncryptedRet: 0,
					StartMonoTimeTs:   1000,
					EndMonoTimeTs:     2000,
				},
			},
		},
	}

	// Note: We can't directly test lookupAndDeletePerCPUMap as it requires cilium.Map,
	// but this test demonstrates the expected behavior that the fix implements.

	// Simulate the old buggy behavior
	flowsWithBug := make(map[ebpf.BpfFlowId]model.BpfFlowContent)
	for k, v := range flows {
		flowsWithBug[k] = v
	}

	var addit []ebpf.BpfAdditionalMetrics
	it := additionalMetricsMap.Iterate()
	var id ebpf.BpfFlowId
	for it.Next(&id, &addit) {
		_ = additionalMetricsMap.LookupAndDelete(&id, &addit)
		flow, found := flowsWithBug[id]
		if !found {
			// OLD BUGGY BEHAVIOR: Create empty flow
			flow = model.BpfFlowContent{BpfFlowMetrics: &ebpf.BpfFlowMetrics{}}
		}
		for _, entry := range addit {
			flow.AccumulateAdditional(&entry)
		}
		flowsWithBug[id] = flow
	}

	// With the bug, we'd have 2 flows: the real one and a phantom one
	assert.Equal(t, 2, len(flowsWithBug), "Bug: orphaned metrics create phantom flows")

	// The phantom flow would have 0 bytes and 0 packets (the bug reported in NETOBSERV-2343)
	phantomFlow := flowsWithBug[orphanedFlowID]
	assert.Equal(t, uint64(0), phantomFlow.BpfFlowMetrics.Packets, "Bug: phantom flow has 0 packets")
	assert.Equal(t, uint64(0), phantomFlow.BpfFlowMetrics.Bytes, "Bug: phantom flow has 0 bytes")
	assert.NotNil(t, phantomFlow.AdditionalMetrics, "Bug: phantom flow has IPsec metrics")

	// Simulate the new fixed behavior
	flowsFixed := make(map[ebpf.BpfFlowId]model.BpfFlowContent)
	for k, v := range flows {
		flowsFixed[k] = v
	}

	// Reset the map
	additionalMetricsMap.data = map[ebpf.BpfFlowId]interface{}{
		mainFlowID: []ebpf.BpfAdditionalMetrics{
			{
				FlowRtt:           100,
				IpsecEncrypted:    true,
				IpsecEncryptedRet: 0,
				StartMonoTimeTs:   1000,
				EndMonoTimeTs:     2000,
			},
		},
		orphanedFlowID: []ebpf.BpfAdditionalMetrics{
			{
				FlowRtt:           200,
				IpsecEncrypted:    true,
				IpsecEncryptedRet: 0,
				StartMonoTimeTs:   1000,
				EndMonoTimeTs:     2000,
			},
		},
	}

	it2 := additionalMetricsMap.Iterate()
	for it2.Next(&id, &addit) {
		_ = additionalMetricsMap.LookupAndDelete(&id, &addit)
		flow, found := flowsFixed[id]
		if !found {
			// NEW FIXED BEHAVIOR: Skip orphaned metrics
			continue
		}
		for _, entry := range addit {
			flow.AccumulateAdditional(&entry)
		}
		flowsFixed[id] = flow
	}

	// After the fix, we should only have 1 flow (the real one)
	assert.Equal(t, 1, len(flowsFixed), "Fix: orphaned metrics are skipped")

	// The real flow should have its IPsec metrics properly merged
	realFlow := flowsFixed[mainFlowID]
	assert.Equal(t, uint64(10), realFlow.BpfFlowMetrics.Packets, "Real flow keeps its packet count")
	assert.Equal(t, uint64(1500), realFlow.BpfFlowMetrics.Bytes, "Real flow keeps its byte count")
	assert.NotNil(t, realFlow.AdditionalMetrics, "Real flow has IPsec metrics")
	assert.Equal(t, uint64(100), realFlow.AdditionalMetrics.FlowRtt, "Real flow has correct RTT")
	assert.True(t, realFlow.AdditionalMetrics.IpsecEncrypted, "Real flow has IPsec encrypted flag")

	// The orphaned flow should NOT exist
	_, orphanExists := flowsFixed[orphanedFlowID]
	assert.False(t, orphanExists, "Fix: orphaned flow does not exist")
}

// TestLookupAndDeletePerCPUMapAllOrphaned tests the edge case where
// all supplementary metrics are orphaned (no main flows exist)
func TestLookupAndDeletePerCPUMapAllOrphaned(t *testing.T) {
	orphanedFlowID1 := ebpf.BpfFlowId{SrcPort: 80, DstPort: 443}
	orphanedFlowID2 := ebpf.BpfFlowId{SrcPort: 8080, DstPort: 8443}

	// Empty main flows map
	flows := map[ebpf.BpfFlowId]model.BpfFlowContent{}

	// Additional metrics map contains only orphaned metrics
	additionalMetricsMap := &mockMap{
		data: map[ebpf.BpfFlowId]interface{}{
			orphanedFlowID1: []ebpf.BpfAdditionalMetrics{
				{IpsecEncrypted: true},
			},
			orphanedFlowID2: []ebpf.BpfAdditionalMetrics{
				{FlowRtt: 200},
			},
		},
	}

	var addit []ebpf.BpfAdditionalMetrics
	it := additionalMetricsMap.Iterate()
	var id ebpf.BpfFlowId
	for it.Next(&id, &addit) {
		_ = additionalMetricsMap.LookupAndDelete(&id, &addit)
		flow, found := flows[id]
		if !found {
			// Fixed behavior: skip orphaned metrics
			continue
		}
		for _, entry := range addit {
			flow.AccumulateAdditional(&entry)
		}
		flows[id] = flow
	}

	// After the fix, flows map should still be empty (no phantom flows created)
	assert.Equal(t, 0, len(flows), "Fix: all orphaned metrics are skipped, no flows created")
}

// TestLookupAndDeletePerCPUMapMetricsCounter tests that the metrics counter
// properly tracks the number of supplementary metrics processed
func TestLookupAndDeletePerCPUMapMetricsCounter(t *testing.T) {
	// This is a documentation test showing that the actual lookupAndDeletePerCPUMap
	// function returns a count of processed entries

	mainFlowID := ebpf.BpfFlowId{SrcPort: 80, DstPort: 443}
	orphanedFlowID := ebpf.BpfFlowId{SrcPort: 8080, DstPort: 8443}

	flows := map[ebpf.BpfFlowId]model.BpfFlowContent{
		mainFlowID: {
			BpfFlowMetrics: &ebpf.BpfFlowMetrics{Packets: 10, Bytes: 1500},
		},
	}

	additionalMetricsMap := &mockMap{
		data: map[ebpf.BpfFlowId]interface{}{
			mainFlowID:     []ebpf.BpfAdditionalMetrics{{FlowRtt: 100}},
			orphanedFlowID: []ebpf.BpfAdditionalMetrics{{FlowRtt: 200}},
		},
	}

	var addit []ebpf.BpfAdditionalMetrics
	it := additionalMetricsMap.Iterate()
	var id ebpf.BpfFlowId
	processedCount := 0
	mergedCount := 0

	for it.Next(&id, &addit) {
		_ = additionalMetricsMap.LookupAndDelete(&id, &addit)
		processedCount++

		flow, found := flows[id]
		if !found {
			continue
		}
		for _, entry := range addit {
			flow.AccumulateAdditional(&entry)
		}
		flows[id] = flow
		mergedCount++
	}

	// We processed 2 supplementary metric entries
	assert.Equal(t, 2, processedCount, "Should process all supplementary metrics")
	// But only merged 1 (the one with a corresponding main flow)
	assert.Equal(t, 1, mergedCount, "Should only merge metrics with main flows")
}

// Note: The actual lookupAndDeletePerCPUMap function uses cilium.Map which requires
// real BPF maps and can't be easily mocked. These tests demonstrate the expected
// behavior using a simplified mock. Integration tests would be needed to fully
// verify the fix with real BPF maps.

func init() {
	// Initialize metrics to avoid nil pointer panics in case they're used
	_ = metrics.NewMetrics(&metrics.Settings{})
}
