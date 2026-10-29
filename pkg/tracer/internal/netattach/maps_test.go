package netattach

import (
	"fmt"
	"os"
	"testing"

	cilium "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
)

func TestMinimizeMapsIfDisabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, floor := range []int{1, os.Getpagesize()} {
			t.Run(fmt.Sprintf("enabled=%t/floor=%d", enabled, floor), func(t *testing.T) {
				spec := sizingTestSpec()
				original := spec.Copy()
				MinimizeMapsIfDisabled(spec, enabled, floor, "first", "second")
				for _, name := range []string{"first", "second"} {
					if !enabled {
						original.Maps[name].MaxEntries = uint32(floor)
					}
				}
				assert.Equal(t, original.Maps, spec.Maps)
			})
		}
	}
}

func TestResizeMaps(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			spec := sizingTestSpec()
			original := spec.Copy()
			ResizeMaps(spec, enabled, 5000, "first", "second")
			expected := uint32(1)
			if enabled {
				expected = 5000
			}
			original.Maps["first"].MaxEntries = expected
			original.Maps["second"].MaxEntries = expected
			assert.Equal(t, original.Maps, spec.Maps)
		})
	}
}

func sizingTestSpec() *cilium.CollectionSpec {
	return &cilium.CollectionSpec{Maps: map[string]*cilium.MapSpec{
		"first":     {Type: cilium.Hash, KeySize: 8, ValueSize: 32, MaxEntries: 16384, Flags: 1},
		"second":    {Type: cilium.PerCPUHash, KeySize: 40, ValueSize: 24, MaxEntries: 65536},
		"unrelated": {Type: cilium.Array, KeySize: 4, ValueSize: 4, MaxEntries: 16},
	}}
}
