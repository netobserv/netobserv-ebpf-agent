package model

import (
	"fmt"
	"strings"
	"testing"
)

func TestSplitFlowBatchRecordsPreservesRecordsWithinBudget(t *testing.T) {
	records := make([]*Record, 32)
	for i := range records {
		records[i] = &Record{Interfaces: []IntfDirUdn{{Interface: fmt.Sprintf("veth-%02d", i), Udn: "test-network"}}}
	}
	targetBytes := EstimateFlowBatchBytes(records[:8:8])

	parts := SplitFlowBatchRecords(records, targetBytes)
	if len(parts) < 2 {
		t.Fatalf("expected multiple parts, got %d", len(parts))
	}

	var index int
	for partIndex, part := range parts {
		if len(part.Records) == 0 {
			t.Fatalf("part %d is empty", partIndex)
		}
		if cap(part.Records) != len(part.Records) {
			t.Fatalf("part %d retains capacity %d for length %d", partIndex, cap(part.Records), len(part.Records))
		}
		if part.EstimatedBytes != EstimateFlowBatchBytes(part.Records) {
			t.Fatalf("part %d has stale estimated size", partIndex)
		}
		if part.EstimatedBytes > targetBytes {
			t.Fatalf("part %d estimated size %d exceeds budget %d", partIndex, part.EstimatedBytes, targetBytes)
		}
		for _, record := range part.Records {
			if record != records[index] {
				t.Fatalf("record %d changed order or identity", index)
			}
			index++
		}
	}
	if index != len(records) {
		t.Fatalf("split preserved %d of %d records", index, len(records))
	}
}

func TestSplitFlowBatchRecordsKeepsSingleOversizedRecord(t *testing.T) {
	record := &Record{Interfaces: []IntfDirUdn{{Interface: strings.Repeat("x", 2048)}}}
	parts := SplitFlowBatchRecords([]*Record{record}, 1)
	if len(parts) != 1 || len(parts[0].Records) != 1 || parts[0].Records[0] != record {
		t.Fatalf("unexpected split for one oversized record: %#v", parts)
	}
	if parts[0].EstimatedBytes <= 1 {
		t.Fatalf("expected oversized part, got %d bytes", parts[0].EstimatedBytes)
	}
}
