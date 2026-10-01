package netattach

import cilium "github.com/cilium/ebpf"

// MinimizeMapsIfDisabled sets disabled maps to floor, leaving enabled maps at
// their existing capacities. Ring buffers need a floor of at least one page.
func MinimizeMapsIfDisabled(spec *cilium.CollectionSpec, enabled bool, floor int, maps ...string) {
	if !enabled {
		for _, name := range maps {
			spec.Maps[name].MaxEntries = uint32(floor)
		}
	}
}

// ResizeMaps sets maps to capacity when enabled, or one entry when disabled.
// Use MinimizeMapsIfDisabled for maps whose enabled capacity comes from the BPF object.
func ResizeMaps(spec *cilium.CollectionSpec, enabled bool, capacity int, maps ...string) {
	if !enabled {
		capacity = 1
	}
	for _, name := range maps {
		spec.Maps[name].MaxEntries = uint32(capacity)
	}
}
