package plaintext

import (
	"strings"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

func TestToMapPreviewBytes(t *testing.T) {
	data := []byte(strings.Repeat("A", 300))
	rec := &model.PlaintextRecord{Data: data, Direction: model.PlaintextDirectionWrite}

	m := ToMap(rec, 256)
	preview, ok := m["PlaintextPreview"].(string)
	if !ok || len(preview) != 256 {
		t.Fatalf("expected 256-byte preview, got %d", len(preview))
	}

	full := ToMap(rec, 0)
	preview, ok = full["PlaintextPreview"].(string)
	if !ok || len(preview) != len(data) {
		t.Fatalf("expected full preview, got %d want %d", len(preview), len(data))
	}
}
