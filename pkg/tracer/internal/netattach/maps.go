package netattach

import (
	"os"

	cilium "github.com/cilium/ebpf"
)

// MinimizeOpenSSLMaps keeps verifier-visible maps when OpenSSL probes are disabled,
// without allocating their normal event buffer and preallocated tracking state.
// Both flow and packet objects use these map names.
func MinimizeOpenSSLMaps(spec *cilium.CollectionSpec) {
	spec.Maps["ssl_data_event_map"].MaxEntries = uint32(os.Getpagesize())
	spec.Maps["ssl_read_active_map"].MaxEntries = 1
	spec.Maps["ssl_fd_map"].MaxEntries = 1
}
