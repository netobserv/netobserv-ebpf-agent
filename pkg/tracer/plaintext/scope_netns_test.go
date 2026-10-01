package plaintext

import (
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

func TestScopeSkipsEnrichWhenKernelTuplePresent(t *testing.T) {
	s := NewScope(nil, "", "", false, 0, 0)
	rec := &model.PlaintextRecord{
		SrcAddr:   "10.244.2.7",
		DstAddr:   "10.244.2.1",
		SrcPort:   8443,
		DstPort:   40494,
		Protocol:  "TCP",
		Direction: model.PlaintextDirectionWrite,
	}
	s.enrichFiveTuple(rec)
	if rec.SrcAddr != "10.244.2.7" || rec.DstPort != 40494 {
		t.Fatalf("kernel tuple should be preserved, got %#v", rec)
	}
}
